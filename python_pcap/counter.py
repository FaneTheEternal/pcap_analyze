from collections import defaultdict, namedtuple

import numpy as np
import pandas as pd


class Count:
    def __init__(self):
        self.IP = 0
        self.IP_WITH_FLAGS = defaultdict(int)
        self.ICMP = 0
        self.TCP = 0
        self.TCP_WITH_FLAGS = defaultdict(int)
        self.UDP = 0
        self.ARP = 0
        self.HTTP = 0
        self.SMTP = 0
        self.DHCP = 0

        self.addresses = set()
        self.ports = set()

        self.BYTES = 0
        self.DATA_BYTES = 0

        self.avg_pkt_size = 0
        self.avg_delta_pkt_size = 0
        self.avg_time = 0
        self.avg_delta_time = 0

    @classmethod
    def spreadsheet_headers(cls):
        return [
            'IP',
            'IP with MF',
            'IP with DF',
            'IP with evil',
            'ICMP',
            'TCP',
            'TCP with F',
            'TCP with S',
            'TCP with R',
            'TCP with P',
            'TCP with A',
            'TCP with U',
            'TCP with E',
            'TCP with C',
            'TCP with N',
            'UDP',
            'ARP',
            'HTTP',
            'SMTP',
            'DHCP',
            'addresses count',
            'ports count',
            'BYTES',
            'DATA_BYTES',
            'Average packet size',
            'Average delta packet size',
            'Average time interval',
            'Average delta time interval',
        ]

    @classmethod
    def generate(cls, packets, period):
        # qualify paths
        from scapy.layers.dhcp import DHCP
        from scapy.layers.http import HTTP
        from scapy.layers.inet import IP, ICMP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether

        c = 0
        count = cls()
        start_stamp = None
        last_stamp = None
        time_intervals = []
        pkt_sizes = []
        pkt: Ether
        for pkt in packets:
            if start_stamp is None:
                start_stamp = pkt.time
                last_stamp = start_stamp
            else:
                time_intervals.append(pkt.time - last_stamp)

            pkt_sizes.append(len(pkt))

            if pkt.haslayer(IP):
                count.IP += 1
                ip: IP = pkt[IP]
                count.IP_WITH_FLAGS[str(ip.flags)] += 1
                count.addresses.update((ip.src, ip.dst))
            if pkt.haslayer(ICMP):
                count.ICMP += 1
            if pkt.haslayer(TCP):
                count.TCP += 1
                tcp: TCP = pkt[TCP]
                count.ports.update((tcp.sport, tcp.dport))
                for f in str(tcp.flags):
                    count.TCP_WITH_FLAGS[f] += 1
                count.DATA_BYTES += len(tcp.payload)
            if pkt.haslayer(UDP):
                count.UDP += 1
                udp: UDP = pkt[UDP]
                count.DATA_BYTES += len(udp.payload)
            if pkt.haslayer(ARP):
                count.ARP += 1
            if pkt.haslayer(HTTP):
                count.HTTP += 1
            # TODO: ? SMTP ? in scapy is not implemented
            if pkt.haslayer(DHCP):
                count.DHCP += 1

            if pkt.time - start_stamp > period:
                pkt_count = cls._compute(count, pkt_sizes, time_intervals)

                # return result & reset counts
                print(f'{c} with {pkt_count}')
                c += 1
                yield count
                count = cls()
                start_stamp = None
                last_stamp = None
                time_intervals = []
                pkt_sizes = []
        if pkt_sizes:
            pkt_count = cls._compute(count, pkt_sizes, time_intervals)
            print(f'{c} with {pkt_count}')
            yield count

    @staticmethod
    def _compute(count, pkt_sizes, time_intervals):
        pkt_count = len(pkt_sizes)
        # sizes
        count.avg_pkt_size = sum(pkt_sizes) / pkt_count
        deltas = map(lambda n: abs(count.avg_pkt_size - n), pkt_sizes)
        count.avg_delta_pkt_size = sum(deltas) / pkt_count
        count.BYTES = sum(pkt_sizes)

        # times
        intervals_count = len(time_intervals)
        count.avg_time = sum(time_intervals) / intervals_count
        deltas = map(lambda t: abs(count.avg_time - t), time_intervals)
        count.avg_delta_time = sum(deltas) / intervals_count
        return pkt_count

    def as_row(self):
        return [
            self.IP,
            self.IP_WITH_FLAGS.get('MF', 0),
            self.IP_WITH_FLAGS.get('DF', 0),
            self.IP_WITH_FLAGS.get('evil', 0),
            self.ICMP,
            self.TCP,
            self.TCP_WITH_FLAGS.get('F', 0),
            self.TCP_WITH_FLAGS.get('S', 0),
            self.TCP_WITH_FLAGS.get('R', 0),
            self.TCP_WITH_FLAGS.get('P', 0),
            self.TCP_WITH_FLAGS.get('A', 0),
            self.TCP_WITH_FLAGS.get('U', 0),
            self.TCP_WITH_FLAGS.get('E', 0),
            self.TCP_WITH_FLAGS.get('C', 0),
            self.TCP_WITH_FLAGS.get('N', 0),
            self.UDP,
            self.ARP,
            self.HTTP,
            self.SMTP,
            self.DHCP,
            len(self.addresses),
            len(self.ports),
            self.BYTES,
            self.DATA_BYTES,
            self.avg_pkt_size,
            self.avg_delta_pkt_size,
            self.avg_time,
            self.avg_delta_time,
        ]


class Counter:
    def __init__(self, period=3):
        self.period = period
        self.counts: list[Count] = []

    def invoke(self, packets):
        self.counts = list(Count.generate(packets, self.period))

    def save_spreadsheet(self, name):
        data = np.array([c.as_row() for c in self.counts])
        df = pd.DataFrame(data, columns=Count.spreadsheet_headers())
        writer = pd.ExcelWriter(f'{name}.xlsx', engine='xlsxwriter')
        df.to_excel(writer)
        writer.save()
