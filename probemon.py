#!/usr/bin/python
#
# CHANGELOG
#
# 2017, July 4, Bifrozt
# - Supressing "WARNING: No route found for IPv6 destination" message
# - Removed long argument options
# - Created logical argument groups
# - Forced argument types where applicable
# - Default size and number of retained logs has been adjusted
#	- Log size: 5000000b to 5242880b (5MB)
#	- Retained logs: 99999 to 200
#	Original default values would have resulted in
#	5000000b * 99999 = 499995000000b (465.65GB)
# - Changed action='store_true' to action='store_false' for
#	- mac-info
#	- ssid
#	- rssi
#	Reason for this is purely sujective to my own usage, using store_false makes
#	the script log this data by default.
# - Checking user privileges before attempting to call socket
# - Removed check for args.interface, argument is now required
#

import argparse
import datetime
import logging
import netaddr
import os
import sys
import time
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from pprint import pprint
from logging.handlers import RotatingFileHandler


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

DEBUG = False

def build_packet_callback(time_fmt, logger, delimiter, mac_info, ssid, rssi):
	def packet_callback(packet):
		
		if not packet.haslayer(Dot11):
			return

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
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

		# parse mac address and look up the organization from the vendor octets
		if mac_info:
			try:
				parsed_mac = netaddr.EUI(packet.addr2)
				fields.append(parsed_mac.oui.registration().org)
			except netaddr.core.NotRegisteredError, e:
				fields.append('UNKNOWN')

		# include the SSID in the probe frame
		if ssid:
			fields.append(packet.info)
			
		if rssi:
			rssi_val = -(256-ord(packet.notdecoded[-4:-3]))
			fields.append(str(rssi_val))

		logger.info(delimiter.join(fields))

	return packet_callback


def main():
	parser = argparse.ArgumentParser(description=DESCRIPTION)

	# Capturing interface options
	cif = parser.add_argument_group('Interface')
	cif.add_argument('-i',
					dest='interface',
					help='Capturing interface',
					required=True
					)

	# Logging options
	log = parser.add_argument_group('Log options')
	log.add_argument('-t',
					dest='time',
					choices=['iso', 'unix'],
					default='iso',
					help='Time format (default: iso)'
					)
	log.add_argument('-o',
					dest='output',
					default='probemon.log',
					help='Log file (default: probemon.log)'
					)
	log.add_argument('-b',
					dest='max_bytes',
					default=5242880,
					type=int,
					help='Log rotation size in bytes (default: 5242880 (5MB))'
					)
	log.add_argument('-c',
					dest='max_backups',
					default=200,
					type=int,
					help='Number log files to keep (default: 200)'
					)
	log.add_argument('-d',
					dest='delimiter',
					default='\t',
					help='Field delimiter (default: \\t)'
					)
	log.add_argument('-f',
					dest='mac_info',
					action='store_false',
					help='Exclude MAC address vendor from output'
					)
	log.add_argument('-s',
					dest='ssid',
					action='store_false',
					help='Exclude SSID probe from output'
					)
	log.add_argument('-r',
					dest='rssi',
					action='store_false',
					help='Exclude rssi from output'
					)

	div = parser.add_argument_group('Additional options')
	div.add_argument('-D',
					dest='debug',
					action='store_true',
					help='Enable debug output'
					)
	div.add_argument('-l',
					dest='log',
					action='store_true',
					help='Enable scrolling live view of the logfile'
					)

	args = parser.parse_args()

	if os.geteuid() != 0:
		print '[FATAL]: You have to be root to run this script'
		sys.exit(1)

	DEBUG = args.debug

	# setup our rotating logger
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	handler = RotatingFileHandler(args.output,
								maxBytes=args.max_bytes,
								backupCount=args.max_backups
								)
	logger.addHandler(handler)
	if args.log:
		logger.addHandler(logging.StreamHandler(sys.stdout))
	built_packet_cb = build_packet_callback(args.time, logger, 
		args.delimiter, args.mac_info, args.ssid, args.rssi)
	sniff(iface=args.interface, prn=built_packet_cb, store=0)


if __name__ == '__main__':
	main()

