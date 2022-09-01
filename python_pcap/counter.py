import numpy as np
import pandas as pd

from scapy.layers.l2 import Ether


class IPFlags(object):
    def __init__(self):
        self.null = 0
        self.df = 0
        self.mf = 0


class TCPFlags(object):
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    def __init__(self):
        self.ns = 0
        self.cwr = 0
        self.ece = 0
        self.urg = 0
        self.ack = 0
        self.psh = 0
        self.rst = 0
        self.syn = 0
        self.fin = 0


class Count:
    def __init__(self):
        self.total = 0

        self.IP = 0
        self.IP_FLAGS = IPFlags()
        self.ICMP = 0
        self.ICMP_REQ = 0
        self.ICMP_RES = 0
        self.TCP = 0
        self.TCP_FLAGS = TCPFlags()
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
            'TOTAL',
            'IP',
            'IP_MF',
            'IP_DF',
            'IP_null',
            'ICMP',
            'ICMP_REQ',
            'ICMP_RES',
            'TCP',
            'TCP_NS',
            'TCP_CWR',
            'TCP_ECE',
            'TCP_URG',
            'TCP_ACK',
            'TCP_PSH',
            'TCP_RST',
            'TCP_SYN',
            'TCP_FIN',
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

    def flush(self, sizes: list[int], intervals: list) -> 'Count':
        pkt_count = len(sizes)

        self.BYTES = sum(sizes)
        self.avg_pkt_size = self.BYTES / pkt_count
        self.avg_delta_pkt_size = \
            sum(map(lambda s: abs(self.avg_pkt_size - s), sizes)) / pkt_count

        self.avg_time = sum(intervals) / max(len(intervals), 1)
        self.avg_delta_time = \
            sum(map(lambda t: abs(self.avg_time - t), intervals)) / max(len(intervals), 1)
        sizes.clear()
        intervals.clear()

        shadow = self.__class__()
        shadow.__dict__.update(self.__dict__)
        self.__dict__.update(self.__class__().__dict__)
        return shadow

    def apply(self, pkt: Ether):
        # qualify paths
        from scapy.layers.dhcp import DHCP
        from scapy.layers.http import HTTP
        from scapy.layers.inet import IP, ICMP, TCP, UDP
        from scapy.layers.l2 import ARP

        self.total += 1
        if pkt.haslayer(IP):
            self.IP += 1
            ip: IP = pkt[IP]
            if str(ip.flags) == 'MF':
                self.IP_FLAGS.mf += 1
            elif str(ip.flags) == 'DF':
                self.IP_FLAGS.df += 1
            elif str(ip.flags) == 'evil':
                self.IP_FLAGS.null += 1
            self.addresses.update((ip.src, ip.dst))
        if pkt.haslayer(ICMP):
            self.ICMP += 1
            icmp: ICMP = pkt[ICMP]
            if icmp.type == 0:
                self.ICMP_RES += 1
            elif icmp.type == 8:
                self.ICMP_REQ += 1
        if pkt.haslayer(TCP):
            self.TCP += 1
            tcp: TCP = pkt[TCP]
            self.ports.update((tcp.sport, tcp.dport))
            f = tcp.flags
            # TODO: NS
            if f & TCPFlags.CWR:
                self.TCP_FLAGS.cwr += 1
            if f & TCPFlags.ECE:
                self.TCP_FLAGS.ece += 1
            if f & TCPFlags.URG:
                self.TCP_FLAGS.urg += 1
            if f & TCPFlags.ACK:
                self.TCP_FLAGS.ack += 1
            if f & TCPFlags.PSH:
                self.TCP_FLAGS.psh += 1
            if f & TCPFlags.RST:
                self.TCP_FLAGS.rst += 1
            if f & TCPFlags.SYN:
                self.TCP_FLAGS.syn += 1
            if f & TCPFlags.FIN:
                self.TCP_FLAGS.fin += 1
            self.DATA_BYTES += len(tcp.payload)
        if pkt.haslayer(UDP):
            self.UDP += 1
            udp: UDP = pkt[UDP]
            self.DATA_BYTES += len(udp.payload)
        if pkt.haslayer(ARP):
            self.ARP += 1
        if pkt.haslayer(HTTP):
            self.HTTP += 1
        # TODO: ? SMTP ? in scapy is not implemented
        if pkt.haslayer(DHCP):
            self.DHCP += 1

    @classmethod
    def generate(cls, packets, period):
        c = 0
        count = cls()
        start_stamp = None
        last_stamp = None
        time_intervals = []
        pkt_sizes = []
        for pkt in packets:  # type: Ether
            c += 1

            if start_stamp is None:
                start_stamp = pkt.time
            else:
                diff = pkt.time - start_stamp
                if diff > period:
                    yield count.flush(pkt_sizes, time_intervals)
                    diff -= period
                    while diff > period:
                        diff -= period
                        yield cls()
                    start_stamp = pkt.time
                    last_stamp = None
            if last_stamp is not None:
                time_intervals.append(pkt.time - last_stamp)
            last_stamp = pkt.time
            pkt_sizes.append(len(pkt))
            count.apply(pkt)

        if pkt_sizes:
            yield count.flush(pkt_sizes, time_intervals)
        # print(f'COUNTS APPLY {c} FRAMES')

    def as_row(self):
        return [
            self.total,
            self.IP,
            self.IP_FLAGS.mf,
            self.IP_FLAGS.df,
            self.IP_FLAGS.null,
            self.ICMP,
            self.ICMP_REQ,
            self.ICMP_RES,
            self.TCP,
            self.TCP_FLAGS.ns,
            self.TCP_FLAGS.cwr,
            self.TCP_FLAGS.ece,
            self.TCP_FLAGS.urg,
            self.TCP_FLAGS.ack,
            self.TCP_FLAGS.psh,
            self.TCP_FLAGS.rst,
            self.TCP_FLAGS.syn,
            self.TCP_FLAGS.fin,
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
