#!/usr/bin/python

import time
import datetime
import argparse
import netaddr
import sys
import logging
from scapy.all import *
from logging.handlers import RotatingFileHandler


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"



def build_packet_callback(time_fmt, logger, delimiter, mac_info, ssid):
	def packet_callback(packet):
		if not packet.haslayer(Dot11):
			return

		if packet.type != 0 or packet.subtype != 0x04:
			return

		# list of output fields
		fields = []

		# determine preferred time format 
		log_time = str(int(time.time()))
		if time_fmt == 'iso':
			log_time = datetime.datetime.now().isoformat()

		fields.append(log_time)

		# append the mac address itself
		fields.append(packet.addr2)

		# parse mac address and look up the organization from the vendor byte
		if mac_info:
			parsed_mac = netaddr.EUI(packet.addr2)
			fields.append(parsed_mac.oui.registration().org)

		# include the SSID in the probe frame
		if ssid:
			fields.append(packet.info)

		logger.info(delimiter.join(fields))

	return packet_callback

def main():
	parser = argparse.ArgumentParser(description=DESCRIPTION)
	parser.add_argument('-i', '--interface', help="capture interface")
	parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
	parser.add_argument('-o', '--output', default='probemon.log', help="logging output location")
	parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
	parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
	parser.add_argument('-d', '--delimiter', default='\t', help="output field delimiter")
	parser.add_argument('-f', '--mac-info', action='store_true', help="include MAC address manufacturer")
	parser.add_argument('-s', '--ssid', action='store_true', help="include probe SSID in output")
	args = parser.parse_args()

	if not args.interface:
		print "error: capture interface not given, try --help"
		sys.exit(-1)

	# setup our rotating logger
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	handler = RotatingFileHandler(args.output, maxBytes=args.max_bytes, backupCount=args.max_backups)
	logger.addHandler(handler)

	built_packet_cb = build_packet_callback(args.time, logger, args.delimiter, args.mac_info, args.ssid)
	sniff(iface=args.interface, prn=built_packet_cb)


if __name__ == '__main__':
	main()