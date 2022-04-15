import sys

from scapy import all as sc

from counter import Counter

packets = sc.PcapReader(sys.argv[1])

counter = Counter()
counter.invoke(packets)
counter.save_spreadsheet(sys.argv[1].split('.')[0])
