#!/usr/bin/python
from scapy.all import *
import random
import time
import logging

# qualify paths
from scapy.layers.dhcp import DHCP
from scapy.layers.http import HTTP
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

TIME = 60 * 60 * 6

conf.verb = 0
ips = ["192.168.16.1", "192.168.72.129"]
not_ips = ["192.168.16.12", "192.168.72.128"]

pkts = []

tick = time.time()
tack = tick
with open('out.txt', 'w') as fout:  # file name
    while tack - tick < TIME:  # interval in sec
        logger.info(f'{tack - tick} / {TIME}')
        logger.info(f'TOTAL: {len(pkts)}')

        NORM = 0b0000
        DELAY = 0b0100
        UNREACH = 0b1000
        PAYLOAD = 0b0010
        RANGE = 0b0001

        t = random.randint(1, 7) if random.random() > 0.5 else 0
        # print(t)

        if t & RANGE != 0:
            ip = not_ips[random.randrange(0, len(not_ips))]
        else:
            ip = ips[random.randrange(0, len(ips))]

        # packet = IP(dst=ip) / ICMP()
        for i in range(random.randint(1, 10)):
            packet = IP(dst=ip) / ICMP()
            # packet.time = time.time()
            # print('send to:', packet.dst)

            if t & PAYLOAD:
                ping = packet / random.randbytes(random.randint(64, 65000))
                # print('payload=', len(ping))
            else:
                ping = packet

            pkts.append(ping)
            reply = sr1(ping, timeout=1)  # timeout

            if reply is not None:
                # print(reply.dst, 'is online')
                t &= ~UNREACH
            else:
                # print('not answer')
                t |= UNREACH

            fout.write(f'{t}\n')
            if reply is not None:
                fout.write(f'{0}\n')
                pkts.append(reply)

            pause = random.random() * 5 if t & DELAY else 1

            # print('pause:', pause)
            time.sleep(pause)

        tack = time.time()
    wrpcap("out.pcap", pkts)
