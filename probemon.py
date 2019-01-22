#!/usr/bin/python

import argparse
import time
from datetime import datetime
import netaddr
import os
import sys
import time
import paho.mqtt.client as mqtt
import json
import struct
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from pprint import pprint
from logging.handlers import RotatingFileHandler


NAME = 'probemon'
DESCRIPTION = "a command line tool for logging 802.11 probe request frames"

client = mqtt.Client()
sensor_data = {'macaddress':"", 'time':"", 'make':"", 'ssid':"", 'rssi':0}

DEBUG = False
def parse_rssi(packet):
    # parse dbm_antsignal from radiotap header
    # borrowed from python-radiotap module
    radiotap_header_fmt = '<BBHI'
    radiotap_header_len = struct.calcsize(radiotap_header_fmt)
    version, pad, radiotap_len, present = struct.unpack_from(radiotap_header_fmt, packet)

    start = radiotap_header_len
    bits = [int(b) for b in bin(present)[2:].rjust(32, '0')]
    bits.reverse()
    if bits[5] == 0:
        return 0

    while present & (1 << 31):
        present, = struct.unpack_from('<I', packet, start)
        start += 4
    offset = start
    if bits[0] == 1:
        offset = (offset + 8 -1) & ~(8-1)
        offset += 8
    if bits[1] == 1:
        offset += 1
    if bits[2] == 1:
        offset += 1
    if bits[3] == 1:
        offset = (offset + 2 -1) & ~(2-1)
        offset += 4
    if bits[4] == 1:
        offset += 2
    dbm_antsignal, = struct.unpack_from('<b', packet, offset)
    return dbm_antsignal

def build_packet_callback(time_fmt, logger, delimiter, mac_info, ssid, rssi, mqtt_topic):
	def packet_callback(packet):

                global sensor_data
                global client

		# we are looking for management frames with a probe subtype
		# if neither match we are done here
		if packet.type != 0 or packet.subtype != 0x04:
			return

		# list of output fields
		fields = []

		# determine preferred time format
		log_time = str(int(time.time()))
		if time_fmt == 'iso':
			log_time = datetime.now().isoformat()

		fields.append(log_time)

		# append the mac address itself
		fields.append(packet.addr2)

		# parse mac address and look up the organization from the vendor octets
		if mac_info:
			try:
				parsed_mac = netaddr.EUI(packet.addr2)
				fields.append(parsed_mac.oui.registration().org)
                                mac_make = str(parsed_mac.oui.registration().org)
			except netaddr.core.NotRegisteredError, e:
				fields.append('UNKNOWN')
                                mac_make = str('UNKNOWN')

		# include the SSID in the probe frame
		if ssid:
			fields.append(packet.info)

                rssi_val = 0
		if rssi:
			rssi_val = parse_rssi(buffer(str(packet)))
			fields.append(str(rssi_val))

                sensor_data['macaddress'] = packet.addr2
                sensor_data['time'] = log_time
                sensor_data['make'] = mac_make.decode("utf-8")
                sensor_data['ssid'] = packet.info.decode("utf-8")
                sensor_data['rssi'] = rssi_val

		logger.info(delimiter.join( [f.decode("utf-8") for f in fields] ))

                client.publish(mqtt_topic, json.dumps( sensor_data ), 1)

	return packet_callback

def main():

        global topic

	parser = argparse.ArgumentParser(description=DESCRIPTION)
	parser.add_argument('-i', '--interface', help="capture interface")
	parser.add_argument('-t', '--time', default='iso', help="output time format (unix, iso)")
	parser.add_argument('-b', '--max-bytes', default=5000000, help="maximum log size in bytes before rotating")
	parser.add_argument('-c', '--max-backups', default=99999, help="maximum number of log files to keep")
	parser.add_argument('-d', '--delimiter', default='\t', help="output field delimiter")
	parser.add_argument('-f', '--mac-info', action='store_true', help="include MAC address manufacturer")
	parser.add_argument('-s', '--ssid', action='store_true', help="include probe SSID in output")
	parser.add_argument('-r', '--rssi', action='store_true', help="include rssi in output")
	parser.add_argument('-D', '--debug', action='store_true', help="enable debug output")
	parser.add_argument('-l', '--log', action='store_true', help="enable scrolling live view of the logfile")
        parser.add_argument('-x', '--mqtt-broker', default='', help="mqtt broker server")
	parser.add_argument('-o', '--mqtt-port', default='1883', help="mqtt broker port")
        parser.add_argument('-u', '--mqtt-user', default='', help="mqtt user")
        parser.add_argument('-p', '--mqtt-password', default='', help="mqtt password")
        parser.add_argument('-m', '--mqtt-topic', default='probemon/request', help="mqtt topic")
	args = parser.parse_args()

	if not args.interface:
		print "error: capture interface not given, try --help"
		sys.exit(-1)

	DEBUG = args.debug

        if args.mqtt_user and args.mqtt_password:
            client.username_pw_set(args.mqtt_user, args.mqtt_password)

        if args.mqtt_broker:
            client.connect(args.mqtt_broker, args.mqtt_port, 1)
            client.loop_start()

	# setup our rotating logger
	logger = logging.getLogger(NAME)
	logger.setLevel(logging.INFO)
	if args.log:
		logger.addHandler(logging.StreamHandler(sys.stdout))
	built_packet_cb = build_packet_callback(args.time, logger,
		args.delimiter, args.mac_info, args.ssid, args.rssi, args.mqtt_topic)
	sniff(iface=args.interface, prn=built_packet_cb, store=0, monitor=True)

if __name__ == '__main__':
	main()
