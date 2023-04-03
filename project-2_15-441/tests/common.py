# Copyright (C) 2022 Carnegie Mellon University
#
# This file is part of the TCP in the Wild course project developed for the
# Computer Networks course (15-441/641) taught at Carnegie Mellon University.
#
# No part of the project may be copied and/or distributed without the express
# permission of the 15-441/641 course staff.

import os
import subprocess

from scapy.all import (
    Packet,
    IntField,
    ShortField,
    StrLenField,
    ByteEnumField,
    bind_layers,
)
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

CODE_DIR = "/vagrant/project-2_15-441"
PCAP = "/vagrant/project-2_15-441/tests/test.pcap"
IFNAME = os.getenv("IFNAME")

# Which host are we running this pytest script on, server or client?
# If we are running pytest on the server VM, we want the testing host to be the
# client VM and vice versa.
HOSTNAME = subprocess.check_output("hostname").strip()
if HOSTNAME.decode("utf-8") == "client":
    TESTING_HOSTNAME = "server"
    HOSTNAME = "client"
elif HOSTNAME.decode("utf-8") == "server":
    TESTING_HOSTNAME = "client"
    HOSTNAME = "server"
else:
    raise RuntimeError(
        f"Unexpected hostname: {HOSTNAME}. You must run these tests in the "
        f"client or server VM."
    )

# You might need to update these for the network setting on your VMs.
IP_ADDRS = {"client": "10.0.1.2", "server": "10.0.1.1"}
MAC_ADDRS = {"client": "08:00:27:a7:fe:b1", "server": "08:00:27:22:47:1c"}
HOST_IP = IP_ADDRS[HOSTNAME]
HOST_MAC = MAC_ADDRS[HOSTNAME]
HOST_PORT = 1234
TESTING_HOST_IP = IP_ADDRS[TESTING_HOSTNAME]
TESTING_HOST_MAC = MAC_ADDRS[TESTING_HOSTNAME]
TESTING_HOST_PORT = 15441

# We can use these commands to start/stop the testing server in a background
# process.
START_TESTING_SERVER_CMD = (
    "tmux new -s pytest_server -d /vagrant/"
    "project-2_15-441/tests/testing_server"
)
STOP_TESTING_SERVER_CMD = "tmux kill-session -t pytest_server"

# Default scapy packets headers we'll use to send packets.
eth = Ether(src=HOST_MAC, dst=TESTING_HOST_MAC)
ip = IP(src=HOST_IP, dst=TESTING_HOST_IP)
udp = UDP(sport=HOST_PORT, dport=TESTING_HOST_PORT)

FIN_MASK = 0x2
ACK_MASK = 0x4
SYN_MASK = 0x8

TIMEOUT = 3

"""
These tests assume there is only one connection in the PCAP
and expects the PCAP to be collected on the server. All of
the basic tests pass on the starter code, without you having
to make any changes. You will need to add to these tests as
you add functionality to your implementation. It is also
important to understand what the given tests are testing for!
"""


# we can make CMUTCP packets using scapy
class CMUTCP(Packet):
    name = "CMU TCP"
    fields_desc = [
        IntField("identifier", 15441),
        ShortField("source_port", HOST_PORT),
        ShortField("destination_port", TESTING_HOST_PORT),
        IntField("seq_num", 0),
        IntField("ack_num", 0),
        ShortField("hlen", 25),
        ShortField("plen", 25),
        ByteEnumField(
            "flags",
            0,
            {
                FIN_MASK: "FIN",
                ACK_MASK: "ACK",
                SYN_MASK: "SYN",
                FIN_MASK | ACK_MASK: "FIN ACK",
                SYN_MASK | ACK_MASK: "SYN ACK",
            },
        ),
        ShortField("advertised_window", 1),
        ShortField("extension_length", 0),
        StrLenField(
            "extension_data",
            None,
            length_from=lambda pkt: pkt.extension_length,
        ),
    ]

    def answers(self, other):
        return isinstance(other, CMUTCP)


bind_layers(UDP, CMUTCP)
