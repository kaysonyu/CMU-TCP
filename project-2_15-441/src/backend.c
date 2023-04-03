/**
 * Copyright (C) 2022 Carnegie Mellon University
 *
 * This file is part of the TCP in the Wild course project developed for the
 * Computer Networks course (15-441/641) taught at Carnegie Mellon University.
 *
 * No part of the project may be copied and/or distributed without the express
 * permission of the 15-441/641 course staff.
 *
 *
 * This file implements the CMU-TCP backend. The backend runs in a different
 * thread and handles all the socket operations separately from the application.
 *
 * This is where most of your code should go. Feel free to modify any function
 * in this file.
 */

#include "backend.h"

#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#include "cmu_packet.h"
#include "cmu_tcp.h"

static bool single = false;

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

struct timeval start_time_client, start_time_server, end_time_;

void init_rtt(cmu_socket_t *sock) {
  sock->estimated_rtt = 1 * 1000 * 1000;  // 初始的Timeout设置为1s
  sock->dev_rtt = 0;
}
// 得到的结果单位为ms，因为主要是在poll里面使用
long getTimeoutInterval(cmu_socket_t *sock) {
  long interval = sock->estimated_rtt + 4 * sock->dev_rtt;

  // printf("TimeoutInterval = %ld ms\n", interval / 1000);
  return interval / 1000;
}

void updateRTT(cmu_socket_t *sock, struct timeval start_time,
               struct timeval end_time) {
  long sampleRTT = (end_time.tv_sec - start_time.tv_sec) * 1000 * 1000 +
                   (end_time.tv_usec - start_time.tv_usec);

  sock->estimated_rtt = sampleRTT / 8 + sock->estimated_rtt * 7 / 8;
  long diff = sock->estimated_rtt - sampleRTT;
  if (diff < 0) diff = -diff;
  sock->dev_rtt = diff / 4 + sock->dev_rtt * 3 / 4;
}

/**
 * Tells if a given sequence number has been acknowledged by the socket.
 *
 * @param sock The socket to check for acknowledgements.
 * @param seq Sequence number to check.
 *
 * @return 1 if the sequence number has been acknowledged, 0 otherwise.
 */
int has_been_acked(cmu_socket_t *sock, uint32_t seq) {
  int result;
  while (pthread_mutex_lock(&(sock->window.ack_lock)) != 0) {
  }
  result = after(sock->window.last_ack_received, seq);
  pthread_mutex_unlock(&(sock->window.ack_lock));
  return result;
}

/**
 * Updates the socket information to represent the newly received packet.
 *
 * In the current stop-and-wait implementation, this function also sends an
 * acknowledgement for the packet.
 *
 * @param sock The socket used for handling packets received.
 * @param pkt The packet data received by the socket.
 */
void handle_message(cmu_socket_t *sock, uint8_t *pkt) {
  cmu_tcp_header_t *hdr = (cmu_tcp_header_t *)pkt;
  uint8_t flags_ = get_flags(hdr);

  switch (flags_) {
    case ACK_FLAG_MASK: {
      uint32_t ack = get_ack(hdr);
      if (after(ack, sock->window.last_ack_received)) {
        sock->window.last_ack_received = ack;
      }
      break;
    }
  }

  if (get_payload_len(pkt) == 0 || get_seq(hdr) != sock->window.next_seq_expected)
    return;

  socklen_t conn_len = sizeof(sock->conn);
  uint32_t seq = sock->window.last_ack_received;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint32_t ack = get_seq(hdr) + get_payload_len(pkt);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint8_t flags = ACK_FLAG_MASK;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *response_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                    ext_data, payload, payload_len);

  sendto(sock->socket, response_packet, plen, 0,
         (struct sockaddr *)&(sock->conn), conn_len);
  free(response_packet);

  seq = get_seq(hdr);

  sock->window.next_seq_expected = seq + get_payload_len(pkt);
  payload_len = get_payload_len(pkt);
  payload = get_payload(pkt);

  // Make sure there is enough space in the buffer to store the payload.
  sock->received_buf =
      realloc(sock->received_buf, sock->received_len + payload_len);
  memcpy(sock->received_buf + sock->received_len, payload, payload_len);
  sock->received_len += payload_len;
}

/**
 * Checks if the socket received any data.
 *
 * It first peeks at the header to figure out the length of the packet and then
 * reads the entire packet.
 *
 * @param sock The socket used for receiving data on the connection.
 * @param flags Flags that determine how the socket should wait for data. Check
 *             `cmu_read_mode_t` for more information.
 */
bool check_for_data(cmu_socket_t *sock, cmu_read_mode_t flags) {
  cmu_tcp_header_t hdr;
  uint8_t *pkt;
  socklen_t conn_len = sizeof(sock->conn);
  ssize_t len = 0;
  uint32_t plen = 0, buf_size = 0, n = 0;

  while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
  }
  switch (flags) {
    case NO_FLAG:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), MSG_PEEK,
                     (struct sockaddr *)&(sock->conn), &conn_len);
      break;
    case TIMEOUT: {
      // Using `poll` here so that we can specify a timeout.
      struct pollfd ack_fd;
      ack_fd.fd = sock->socket;
      ack_fd.events = POLLIN;
      // Timeout after 3 seconds.
      if (poll(&ack_fd, 1, getTimeoutInterval(sock)) <= 0) {
        break;
        return true;
      }
    }
    // Fallthrough.
    case NO_WAIT:
      len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t),
                     MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                     &conn_len);
      break;
    default:
      perror("ERROR unknown flag");
  }
  if (len >= (ssize_t)sizeof(cmu_tcp_header_t)) {
    plen = get_plen(&hdr);
    pkt = malloc(plen);
    while (buf_size < plen) {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                   (struct sockaddr *)&(sock->conn), &conn_len);
      buf_size = buf_size + n;
    }
    handle_message(sock, pkt);
    free(pkt);
  }
  pthread_mutex_unlock(&(sock->recv_lock));
  return false;
}

/**
 * Breaks up the data into packets and sends a single packet at a time.
 *
 * You should most certainly update this function in your implementation.
 *
 * @param sock The socket to use for sending data.
 * @param data The data to be sent.
 * @param buf_len The length of the data being sent.
 */
void single_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  if (buf_len > 0) {
    while (buf_len != 0) {
      uint16_t payload_len = MIN(buf_len, MSS);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = sock->window.last_ack_received;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = 1;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);
      buf_len -= payload_len;

      while (1) {
        // FIXME: This is using stop and wait, can we do better?
        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn),
               conn_len);
        check_for_data(sock, TIMEOUT);
        if (has_been_acked(sock, seq)) {
          break;
        }
      }

      data_offset += payload_len;
    }
  }
}

void window_send(cmu_socket_t *sock, uint8_t *data, int buf_len) {
  uint8_t *msg;
  uint8_t *data_offset = data;
  size_t conn_len = sizeof(sock->conn);

  int sockfd = sock->socket;
  while (buf_len > 0) {
    int order = 0;

    struct timeval start_time, end_time;
    bool have_end_time = false;

    uint32_t old_last_ack_received = sock->window.last_ack_received;

    // 每一组的发送量：全部发送或窗口大小
    int bytes_to_send = MIN(buf_len, WINDOW_INITIAL_WINDOW_SIZE);

    // 已发送的数据量
    gettimeofday(&start_time, NULL);
    int bytes_sent = 0;
    while (bytes_sent < bytes_to_send) {
      // 每次的发送量：本组剩余的或MSS
      uint16_t payload_len = MIN(MSS, bytes_to_send - bytes_sent);

      uint16_t src = sock->my_port;
      uint16_t dst = ntohs(sock->conn.sin_port);
      uint32_t seq = old_last_ack_received + bytes_sent;
      uint32_t ack = sock->window.next_seq_expected;
      uint16_t hlen = sizeof(cmu_tcp_header_t);
      uint16_t plen = hlen + payload_len;
      uint8_t flags = 0;
      uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
      uint16_t ext_len = 0;
      uint8_t *ext_data = NULL;
      uint8_t *payload = data_offset + bytes_sent;

      msg = create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window,
                          ext_len, ext_data, payload, payload_len);

      sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);

      bytes_sent += payload_len;
      order++;
    }

    for (int i = 0; i < order; i++) {

      //超时
      if (check_for_data(sock, TIMEOUT)) {
        break;
      }

      //记录RRT
      if (i == 0 && has_been_acked(sock, old_last_ack_received)) {
        have_end_time = true;
        gettimeofday(&end_time, NULL);
      }

      //本组全部ack
      if (has_been_acked(sock, old_last_ack_received + bytes_to_send)) {
        break;
      }
    }

    //更新RTT
    if (have_end_time) {
      updateRTT(sock, start_time, end_time);
    }

    // 更新窗口开始与数据长度
    int succ_bytes_to_send = sock->window.last_ack_received - old_last_ack_received;
    buf_len -= succ_bytes_to_send;
    data_offset += succ_bytes_to_send;

    // data_offset += bytes_to_send;
    // buf_len -= bytes_to_send;
  }
}

// 第一次握手，供发送方用
void SYN_send(cmu_socket_t *sock) {
  uint8_t flags = SYN_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = 0;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *SYN_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                    ext_data, payload, payload_len);

  sendto(sock->socket, SYN_packet, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);

  cmu_tcp_header_t *header = (cmu_tcp_header_t *)SYN_packet;
  printf("send SYN packet with seq=%d\n", get_seq(header));

  free(SYN_packet);
}
// 接收第二次握手的结果，供发送方用
bool SYN_AND_ACK_rcvd(cmu_socket_t *sock) {
  cmu_tcp_header_t hdr;
  socklen_t conn_len = sizeof(sock->conn);
  int len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)(&sock->conn), &conn_len);
  if (len <= 0) return false;
  if (!(get_flags(&hdr) & (SYN_FLAG_MASK | ACK_FLAG_MASK))) return false;
  if (!(get_ack(&hdr) == sock->window.last_ack_received + 1)) return false;

  printf("SYN_AND_ACK_rcvd: seq=%d ack=%d\n", get_seq(&hdr), get_ack(&hdr));
  // 注意修改滑动窗口中的内容
  sock->window.last_ack_received = get_ack(&hdr);
  sock->window.next_seq_expected = get_seq(&hdr) + 1;
  return true;
}
// 第三次握手，供发送方用
void Third_ACK_send(cmu_socket_t *sock) {
  uint8_t flags = ACK_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *ACK_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                    ext_data, payload, payload_len);

  sendto(sock->socket, ACK_packet, plen, 0, (struct sockaddr *)&(sock->conn),
         conn_len);

  cmu_tcp_header_t *header = (cmu_tcp_header_t *)ACK_packet;
  printf("send ACK packet with seq=%d ack=%d\n", get_seq(header),
         get_ack(header));

  free(ACK_packet);
}
// 接收第一次握手的结果，供接收方用
bool SYN_rcvd(cmu_socket_t *sock) {
  cmu_tcp_header_t hdr;
  socklen_t conn_len = sizeof(sock->conn);
  int len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)&(sock->conn), &conn_len);
  if (len <= 0) return false;
  if (!(get_flags(&hdr) & SYN_FLAG_MASK)) return false;

  printf("SYN_rcvd: seq=%d\n", get_seq(&hdr));
  // 虽然接收到的不是ACK，但是期望的下一个seq号还是要++。
  sock->window.next_seq_expected = get_seq(&hdr) + 1;
  return true;
}
// 第二次握手，供接收方用
void SYN_AND_ACK_send(cmu_socket_t *sock) {
  uint8_t flags = SYN_FLAG_MASK | ACK_FLAG_MASK;
  uint32_t seq = sock->window.last_ack_received;
  uint32_t ack = sock->window.next_seq_expected;

  // No payload.
  uint8_t *payload = NULL;
  uint16_t payload_len = 0;

  // No extension.
  uint16_t ext_len = 0;
  uint8_t *ext_data = NULL;

  socklen_t conn_len = sizeof(sock->conn);
  uint16_t src = sock->my_port;
  uint16_t dst = ntohs(sock->conn.sin_port);
  uint16_t hlen = sizeof(cmu_tcp_header_t);
  uint16_t plen = hlen + payload_len;
  uint16_t adv_window = WINDOW_INITIAL_WINDOW_SIZE;
  uint8_t *SYN_ACK_packet =
      create_packet(src, dst, seq, ack, hlen, plen, flags, adv_window, ext_len,
                    ext_data, payload, payload_len);

  sendto(sock->socket, SYN_ACK_packet, plen, 0,
         (struct sockaddr *)&(sock->conn), conn_len);

  cmu_tcp_header_t *header = (cmu_tcp_header_t *)SYN_ACK_packet;
  printf("send SYN_ACK packet with seq=%d ack=%d\n", get_seq(header),
         get_ack(header));

  struct pollfd ack_fd;
  ack_fd.fd = sock->socket;
  ack_fd.events = POLLIN;
  // 超时重传
  while (poll(&ack_fd, 1, getTimeoutInterval(sock)) == 0) {
    sendto(sock->socket, SYN_ACK_packet, plen, 0,
           (struct sockaddr *)&(sock->conn), conn_len);
    printf("TIMEOUT resend SYN_ACK packet\n");
  }

  free(SYN_ACK_packet);
}
// 确认第三次握手，供接收方用
bool Third_ACK_rcvd(cmu_socket_t *sock) {
  // receive ACK packet
  // check ack
  // set last_ack_received
  cmu_tcp_header_t hdr;
  socklen_t conn_len = sizeof(sock->conn);
  int len = recvfrom(sock->socket, &hdr, sizeof(cmu_tcp_header_t), 0,
                     (struct sockaddr *)&(sock->conn), &conn_len);
  if (len <= 0) return false;
  if (!(get_flags(&hdr) & ACK_FLAG_MASK)) return false;
  if (!(get_ack(&hdr) == sock->window.last_ack_received + 1)) return false;

  printf("Third_ACK_rcvd: seq=%d ack=%d\n", get_seq(&hdr), get_ack(&hdr));
  sock->window.last_ack_received = get_ack(&hdr);
  return true;
}

// 返回值为true表示成功握手，返回值为false表示握手失败
bool handshake(cmu_socket_t *sock) {
  if (sock->type == TCP_INITIATOR) {
    // 发起方
    // 1.发起第一次握手，SYN位有效
    SYN_send(sock);
    // 2.接收方发来SYN和ACK有效的报文
    if (!SYN_AND_ACK_rcvd(sock)) return false;
    gettimeofday(&start_time_client, NULL);
    // 3.发送第三次握手
    Third_ACK_send(sock);
  } else if (sock->type == TCP_LISTENER) {
    // 接收方/监听方
    // 1.
    if (!SYN_rcvd(sock)) return false;
    gettimeofday(&start_time_server, NULL);
    // 2.
    SYN_AND_ACK_send(sock);
    // 3.
    if (!Third_ACK_rcvd(sock)) return false;
  } else {  // 不应进入这个分支
    printf("error sock type!!!\n");
    return false;
  }
  return true;
}

void *begin_backend(void *in) {
  cmu_socket_t *sock = (cmu_socket_t *)in;
  int death, buf_len, send_signal;
  uint8_t *data;
  //--------------初始化rtt信息
  if (!single) {
    init_rtt(sock);
    //--------------准备进行三次握手
    bool succ = handshake(sock);
    if (!succ) {
      cmu_close(sock);
      pthread_exit(NULL);
      return NULL;
    }
  }

  //----------------完成三次握手

  while (1) {
    while (pthread_mutex_lock(&(sock->death_lock)) != 0) {
    }
    death = sock->dying;
    pthread_mutex_unlock(&(sock->death_lock));

    while (pthread_mutex_lock(&(sock->send_lock)) != 0) {
    }
    buf_len = sock->sending_len;

    if (death && buf_len == 0) {
      break;
    }

    if (buf_len > 0) {
      data = malloc(buf_len);
      memcpy(data, sock->sending_buf, buf_len);
      sock->sending_len = 0;
      free(sock->sending_buf);
      sock->sending_buf = NULL;
      pthread_mutex_unlock(&(sock->send_lock));
      if (single)
        single_send(sock, data, buf_len);
      else
        window_send(sock, data, buf_len);
      free(data);
    } else {
      pthread_mutex_unlock(&(sock->send_lock));
    }

    check_for_data(sock, NO_WAIT);

    while (pthread_mutex_lock(&(sock->recv_lock)) != 0) {
    }

    send_signal = sock->received_len > 0;

    pthread_mutex_unlock(&(sock->recv_lock));

    if (send_signal) {
      pthread_cond_signal(&(sock->wait_cond));
    }
  }
  pthread_exit(NULL);
  return NULL;
}
