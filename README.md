# Port Scan Detector

Runs on Python 2.7 using **dpkt**.

Detects IP addresses that may be executing TCP SYN port scans.

Simple usage through [pipenv](https://pipenv.readthedocs.io/en/latest/):

	$ pipenv install
	$ pipenv run ./detector.py pcap_file

## In Detail

In a SYN scan, the scanner generates SYN packets to the various ports for a target host. If a port is open, the host will reply with a SYN-ACK packet and the scanner immediately replies with a RST packet to close the connection. Otherwise, if the port is closed, the host just replies with a RST packet.

Typically, a much smaller number of hosts will actually respond with a SYN-ACK packet in comparison with the number of SYN packets sent out by the scanner. This program will detect that effect.

Also see [this](https://en.wikipedia.org/wiki/Port_scanner#SYN_scanning) on SYN scans.

# Usage

	$ ./detector.py pcap_file [syn_synack_ratio]

Optionally, you can control for the ratio between the number of SYN packets versus the number of SYN-ACK packets that would flag an IP as suspect. By default, this value is 3 (i.e., suspects sent at least 3 times more SYN
packets than than the number of SYN-ACK packets they received.)

## Example

The capture file used in this example is provided as `packets.pcap.xz` in the repo. Note that the file is somewhat large uncompressed (~350MB) and the detector script may take 1-3 minutes to run.

	$ ./detector.py packets.pcap

	Analyzed 5700526 packets:
	128.3.23.2      had 16 SYNs and 0 SYN-ACKs
	128.3.23.5      had 34 SYNs and 1 SYN-ACKs
	128.3.23.117    had 44 SYNs and 8 SYN-ACKs
	128.3.23.158    had 23 SYNs and 2 SYN-ACKs
	128.3.164.248   had 4 SYNs and 0 SYN-ACKs
	128.3.164.249   had 1 SYNs and 0 SYN-ACKs
