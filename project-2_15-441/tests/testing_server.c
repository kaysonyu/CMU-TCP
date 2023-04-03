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
 * This file implements a simple CMU-TCP server used for testing.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cmu_tcp.h"

/*
 * Param: sock - used for reading and writing to a connection
 *
 *
 */
void functionality(cmu_socket_t *sock) {
  uint8_t buf[9898];
  FILE *fp;
  int n;
  int read;

  // Wait to hear from an initiator
  n = 0;
  while (n == 0) {
    n = cmu_read(sock, buf, 9898, NO_FLAG);
  }

  printf("read something %d\n", n);
  // Send over a random file
  fp = fopen("/vagrant/project-2_15-441/tests/random.input", "rb");
  read = 1;
  while (read > 0) {
    read = fread(buf, 1, 2000, fp);
    if (read > 0) cmu_write(sock, buf, read);
  }
}

/*
 * Param: argc - count of command line arguments provided
 * Param: argv - values of command line arguments provided
 *
 * Purpose: To provide a sample listener for the TCP connection.
 *
 */
int main() {
  int portno;
  char *serverip;
  char *serverport;
  cmu_socket_t socket;

  serverip = getenv("server15441");
  if (!serverip) {
    serverip = "10.0.1.1";
  }

  serverport = getenv("serverport15441");
  if (!serverport) {
    serverport = "15441";
  }
  portno = (uint16_t)atoi(serverport);

  printf("starting initiator\n");
  if (cmu_socket(&socket, TCP_LISTENER, portno, serverip) < 0)
    exit(EXIT_FAILURE);
  printf("finished socket\n");
  functionality(&socket);

  sleep(5);

  if (cmu_close(&socket) < 0) exit(EXIT_FAILURE);
  return EXIT_SUCCESS;
}
