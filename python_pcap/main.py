import sys
from time import sleep

from scapy import all as sc

from counter import Counter, Count

period = int(sys.argv[1])

print(*Count.spreadsheet_headers())

while True:
    capture = sc.sniff(timeout=period)
    sleep(period)
    stats = Counter(period + 1)
    stats.invoke(capture)
    stats = stats.counts[0]
    print(*stats.as_row())

