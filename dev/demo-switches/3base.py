#3base.py and app.cfg originally retreived from https://github.com/Matt-Claiborne/Ryu-App/blob/master/3base.py

import logging
import struct
import array
import socket
import signal
import sys
import time
import thread
import ConfigParser

from pprint import pprint

from ryu.base import app_manager
from ryu.controller import mac_to_port, ofp_event, handler
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, HANDSHAKE_DISPATCHER, set_ev_cls
from ryu.controller.ofp_event import EventOFPSwitchFeatures
#from ryu.controller.network import EventMacAddress
from ryu.lib.ip import ipv4_to_bin
from ryu.lib.mac import haddr_to_str, haddr_to_bin
from ryu.lib.packet import packet, lldp, ethernet
from ryu.ofproto import ofproto_v1_3, inet, ether
from ryu.utils import hex_array
from binascii import hexlify

RUNNING = True
# Define a function for the thread

class MySwitch(app_manager.RyuApp):
	OFP_VERSIONS 	= [ofproto_v1_3.OFP_VERSION]	
	DEBUG_LEVEL 	= 3
	mac_to_port	= {}
	dptable 	= {}
	tables 		= {}

	def signal_handler(signal, frame):	
		global RUNNING
		if RUNNING:
		#need a better way to handle this
			print 'Exiting... press ctrl+c again to exit immediatly'
			#self.disconnectAllDevices()
			RUNNING = False
		else:
			raise SystemExit

	signal.signal(signal.SIGINT, signal_handler)


	def ipv6convert(self, ipsrc):
		ipsrc = "".join([hex(ord(c))[2:].zfill(2) for c in ipsrc]) 
		ipsrc = ( int(ipsrc[0:4], 16), int(ipsrc[4:8], 16), int(ipsrc[8:12], 16), int(ipsrc[12:16], 16), int(ipsrc[16:20], 16), int(ipsrc[20:24], 16), int(ipsrc[24:28], 16), int(ipsrc[28:32], 16) )  

		return ipsrc


	def filter_non_printable(self, str):
		return ''.join([c for c in str if (ord(c) > 31 or ord(c) == 9) and ord(c) < 127])
  		#return str.strip('\255')


	def periodicStats( self, threadName, delay):
		count = 0
		while RUNNING:
			count += 1
			print "%s: %s (%d)" % ( threadName, time.ctime(time.time()), count )
			#printConnectedDevices()
			time.sleep(delay)

			if ( (count % self.PeriodicStatsRequestTime) == 0):
				if (self.sendPeriodicStatsRequest):
					self.sendPeriodicStatsRequests()

		sys.exit("GoodBye")


	#Initialization function for APP, define some 'global' variables for later use.
	def __init__(self, *args, **kwargs):
		super(MySwitch, self).__init__(*args, **kwargs)

		config = ConfigParser.RawConfigParser()
		configFileName = 'binaries/ryu/ryu/app/demo/app.cfg'
		print "Loading config file [%s]" % (configFileName)
		config.read(configFileName)

		self.sendDefaultTableMissFlow  	= config.getboolean('global', 'sendDefaultTableMissFlow')
		self.ipControlTableMode		= config.getboolean('global', 'ipControlTableMode')
		self.sendARPPerVLANFlow		= config.getboolean('global', 'sendARPPerVLANFlow')
		self.sendLLDPDiscoveryFrames	= config.getboolean('global', 'sendLLDPDiscoveryFrames')
		self.sendPeriodicStatsRequest	= config.getboolean('global', 'sendPeriodicStatsRequest')
		self.DEBUG_LEVEL		= config.getint('global', 'DEBUG_LEVEL')
		self.numSoftwareTables 		= config.getint('global', 'numSoftwareTables')
		self.defaultARPVLAN		= [int(n) for n in config.get('global', 'defaultARPVLAN').split()]
		self.PeriodicStatsRequestTime	= config.getint('global', 'PeriodicStatsRequestTime')

		print "\t[DEBUG_LEVEL=%s]" % (self.DEBUG_LEVEL)
		print "\t[sendDefaultTableMissFlow=%s]" % (self.sendDefaultTableMissFlow)
		print "\t[ipControlTableMode=%s]" % (self.ipControlTableMode)
		print "\t[sendARPPerVLANFlow=%s]" % (self.sendARPPerVLANFlow)
		print "\t[sendLLDPDiscoveryFrames=%s]" % (self.sendLLDPDiscoveryFrames)
		print "\t[sendPeriodicStatsRequest=%s]" % (self.sendPeriodicStatsRequest)
		print "\t[numSoftwareTables=%s]" % (self.numSoftwareTables)
		print "\t[defaultARPVLAN=%s]" % (self.defaultARPVLAN)
		print "\t[PeriodicStatsRequestTime=%s]" % (self.PeriodicStatsRequestTime)

		
		self.tables[100] = ["goto", 200]
		if self.ipControlTableMode:
			self.tables[101] = ["goto", 200]
			self.tables[102] = ["goto", 200]		
		if self.numSoftwareTables > 1:
			for n in range(200, 199+self.numSoftwareTables):
				self.tables[n] = ["goto", n+1]
		self.tables[199+self.numSoftwareTables] = ["output", ofproto_v1_3.OFPP_CONTROLLER]

		print "Default Tables"
		for table in sorted(self.tables):
			print "\tTable[%s] = %s" % (table, self.tables[table])

		# Create Thread
		try:
		   thread.start_new_thread( self.periodicStats, ("Time Stamp", 1, ) )
		except:
		   print "Error: unable to start stats thread"

					
	#Print console log message with some info appended based on flags
	def printme(self, msg, dp=0, msgLevel=0):
		if (msgLevel <= self.DEBUG_LEVEL):
			if ( (dp==0) | (dp==None) ):
				self.logger.info("\t%s", msg)
			elif (dp==-1):
				self.logger.info("[INFO]: %s", msg)
			else:
				self.logger.info("[0x%016x] %s: %s", dp.id, dp.address, msg)
			return
 
 
	def matchtostring(self, match):
		print match
		print (vars(match))
		matches = [] 		
		try:
			for f in match.fields:
				matches.append('%s: value=%s' % (f.__class__.__name__, f.value))
		except:
			print ""

  		return matches


 	def createHubFlows(self, datapath, ports, vid):
 		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser	
 		self.printme("Creating HUB flows\n\t[ports=%s]" % (ports), datapath)
 		
 		if ( len(ports) <= 1 ):
 			self.printme("ERROR: Creating hub flows requires more than 1 port!")
 			return
 			
 		for port in ports:
			match = ofp_parser.OFPMatch()	
			match.set_in_port(port)
			match.set_vlan_vid(vid)
			actions = []
			for out_port in ports:
				if (out_port != port):
					actions += [ofp_parser.OFPActionOutput(out_port, 0)] 
					
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
			self.send_flow_mod(datapath, match, actions, inst, 0, 0, 0x02)


 	def createFanoutFlows(self, datapath, srcPort, ports, vid):
 		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser	
 		self.printme("Creating Fanout flows\n\t[srcPort=%s][ports=%s]" % (srcPort, ports), datapath)
 
 		for port in ports:
			match = ofp_parser.OFPMatch()	
			match.set_in_port(port)
			match.set_vlan_vid(vid)
			actions = [ofp_parser.OFPActionOutput(srcPort, 0)] 
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
			self.send_flow_mod(datapath, match, actions, inst, 0, 0, 0x03)


		match = ofp_parser.OFPMatch()	
		match.set_in_port(srcPort)
		match.set_vlan_vid(vid)
		actions = []
		for port in ports:
			actions += [ofp_parser.OFPActionOutput(port, 0)] 

		inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		self.send_flow_mod(datapath, match, actions, inst, 0, 0, 0x03)


 	def printConnectedDevices(self):
 		self.printme("Connected Devices", -1, 0)
		for dp in self.dptable:
			self.printme("%s - %s" % (dp, self.dptable[dp].address), 0, 0 ) 


 	def disconnectAllDevices(self):
 		self.printme("Disconnecting Devices")
		for dp in self.dptable:
			self.dptable[dp].is_active = False


 	def sendPeriodicStatsRequests(self): 		
 		self.printConnectedDevices()
 		for dp in self.dptable:
 			if self.dptable[dp].is_active:
				self.printme("Periodoc Requests", self.dptable[dp], 0)
				self.send_group_stats_request(self.dptable[dp])
				self.send_table_stats_request(self.dptable[dp])
				self.send_barrier_request(self.dptable[dp])
				#self.send_flow_stats_request(self.dptable[dp])
				#self.send_barrier_request(self.dptable[dp])
				#self.send_aggregate_stats_request(self.dptable[dp])	
				#self.send_barrier_request(self.dptable[dp])
				self.send_get_config_request(self.dptable[dp])		
				self.send_barrier_request(self.dptable[dp])
				self.send_port_desc_stats_request(self.dptable[dp]) 
				self.send_barrier_request(self.dptable[dp])
				self.send_group_features_stats_request(self.dptable[dp])
				self.send_barrier_request(self.dptable[dp])			
			#self.disconnectAllDevices()


 	#Tests to do on connection with switch
 	def clientConnected(self, datapath):
		self.mac_to_port.setdefault(datapath, {})
		self.dptable[datapath.id] = datapath
		self.printConnectedDevices()		
		self.send_role_request(datapath)
		self.send_set_config(datapath)
		self.send_barrier_request(datapath)
		self.send_get_config_request(datapath)
		self.send_get_async_request(datapath)
		self.send_barrier_request(datapath)		
		self.send_meter_features_stats_request(datapath)
		self.send_group_features_stats_request(datapath)
		self.send_table_features_stats_request(datapath)				
		#self.send_flow_stats_request(datapath)		
		self.send_delete_all_flow_mod(datapath)
		self.send_barrier_request(datapath)

		if (self.sendDefaultTableMissFlow):
			self.send_default_flow_mod(datapath)

		if (self.sendARPPerVLANFlow):
			self.send_default_arp_mod(datapath, self.defaultARPVLAN)
		
		self.send_barrier_request(datapath)

		self.send_port_stats_request(datapath)
		self.send_port_desc_stats_request(datapath)
		self.send_group_stats_request(datapath)
		self.send_table_stats_request(datapath)
		#self.send_flow_stats_request(datapath)
		#self.send_aggregate_stats_request(datapath)
		self.send_barrier_request(datapath)

		#Test setups
		#self.send_echo_request(msg.datapath, "PING-DATA-REQUEST")
		#self.send_packet_out(msg.datapath, 0xffffffff, 0)
		#self.send_table_mod(msg.datapath)
		
		
		#for n in range(1,100):
		#	self.send_raw_packet_out(datapath, 0xffffffff, 0)
		#ADD groups for testing
		#for n in range(1,10):
		#	self.send_group_mod(datapath, n, datapath.ofproto.OFPFC_ADD)
		#self.send_flow_mod(msg.datapath)
		
		#self.createHubFlows(datapath, range(1,18), 1)
		#self.createFanoutFlows(datapath, 1, range(2,5), 1)
		#self.send_test_ip_flow_mod(datapath)


	@set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
	def barrier_reply_handler(self, ev):
		#print vars(ev.msg)
		self.printme('OFPBarrierReply received', ev.msg.datapath, 1)


	@set_ev_cls(ofp_event.EventOFPGetAsyncReply, MAIN_DISPATCHER)
	def get_async_reply_handler(self, ev):
		msg = ev.msg
		self.printme('OFPGetAsyncReply received:\n\tpacket_in_mask=[0x%08x, 0x%08x] port_status_mask=[0x%08x, 0x%08x] flow_removed_mask=[0x%08x, 0x%08x]' %
			(msg.packet_in_mask[0], msg.packet_in_mask[1], msg.port_status_mask[0], msg.port_status_mask[1], msg.flow_removed_mask[0], msg.flow_removed_mask[1]), msg.datapath, 1 )


	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def main_switch_features_handler(self, ev):
		msg = ev.msg
		self.printme('OFPSwitchFeatures received:', msg.datapath, 0)
		self.printme('datapath_id=0x%016x n_buffers=%d n_tables=%d auxiliary_id=%d capabilities=0x%08x' % (msg.datapath_id, msg.n_buffers, msg.n_tables, msg.auxiliary_id, msg.capabilities), 0, 1)


	@set_ev_cls(ofp_event.EventOFPGetConfigReply, MAIN_DISPATCHER)
	def get_config_reply_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto

		if msg.flags == ofp.OFPC_FRAG_NORMAL:
			flags = 'NORMAL'
		elif msg.flags == ofp.OFPC_FRAG_DROP:
			flags = 'DROP'
		elif msg.flags == ofp.OFPC_FRAG_REASM:
			flags = 'REASM'
		elif msg.flags == ofp.OFPC_FRAG_MASK:
			flags = 'MASK'
		else:
			flags = 'unknown'
		
		self.printme('OFPGetConfigReply received:', dp, 0)
		self.printme('flags=%s miss_send_len=%d' % (flags, msg.miss_send_len), 0, 1)


	@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
	def flow_stats_reply_handler(self, ev):		
		self.show_flow_stats(ev.msg.body, ev.msg.datapath)


	@set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
	def aggregate_stats_reply_handler(self, ev):		
		self.show_aggregate_stats(ev.msg.body, ev.msg.datapath)


	@set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
	def port_stats_reply_handler(self, ev):
		self.show_port_stats(ev.msg.body, ev.msg.datapath)


	@set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
	def port_desc_stats_reply_handler(self, ev):
		self.show_port_desc(ev.msg.body, ev.msg.datapath)


	@set_ev_cls(ofp_event.EventOFPGroupStatsReply, MAIN_DISPATCHER)
	def group_stats_reply_handler(self, ev):
		self.show_group_stats(ev.msg.body, ev.msg.datapath)


	@set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
	def table_stats_reply_handler(self, ev):
		self.show_table_stats(ev.msg.body, ev.msg.datapath)			

	@set_ev_cls(ofp_event.EventOFPTableFeaturesStatsReply, MAIN_DISPATCHER)
	def table_features_stats_reply_handler(self, ev):
		self.table_features_stats(ev.msg.body, ev.msg.datapath)	
	
	
	@set_ev_cls(ofp_event.EventOFPMultipartReply, MAIN_DISPATCHER)
	def multipart_reply_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto

		self.printme('OFPMultipartReply received:\n\t%s' % (msg._type), dp, 0 )

		if msg._type == ofp.OFPMP_FLOW:
			self.show_flow_stats(msg.body, dp)
		elif msg._type == ofp.OFPMP_AGGREGATE:
			self.show_aggregate_stats(msg.body, dp)
		elif msg._type == ofp.OFPMP_PORT_STATS:
			self.show_port_stats(msg.body, dp)
		elif msg._type == ofp.OFPMP_PORT_DESC:
			self.show_port_desc(msg.body, dp)
		elif msg._type == ofp.OFPMP_GROUP:
			self.show_group_stats(msg.body, dp)	
		elif msg._type == ofp.OFPMP_GROUP_FEATURES:
			self.show_group_features_stats(msg.body, dp)
		elif msg._type == ofp.OFPMP_TABLE:
			self.show_table_stats(msg.body, dp)	
		elif msg._type == ofp.OFPMP_METER_FEATURES:
			self.show_meter_features_stats(msg.body, dp)
		else:
			self.printme("ERROR in multipartreply decoding TYPE=%x" % (msg.type), dp)


	@set_ev_cls(ofp_event.EventOFPRoleReply, MAIN_DISPATCHER)
	def role_reply_handler(self, ev):
		self.printme('OFPRoleReply received', ev.msg.datapath, 0)
		self.printme('%s' % (ev.msg.role), 0, 1)


	@set_ev_cls(ofp_event.EventOFPEchoRequest,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
	def echo_request_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		self.printme('OFPEchoRequest received:', msg.datapath, 2 )
		self.printme('data=%s' % (hex_array(msg.data)), 0, 2)				
		self.send_echo_reply(dp, msg.data + "PING-DATA-REPLY")


	@set_ev_cls(ofp_event.EventOFPEchoReply,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
	def echo_reply_handler(self, ev):
		msg = ev.msg
		self.printme('OFPEchoReply received:\n\tdata=%s' % (hex_array(msg.data)), msg.datapath, 2 )


	@set_ev_cls(ofp_event.EventOFPHello, HANDSHAKE_DISPATCHER)
	def hello_handler(self, ev):
		msg = ev.msg
		self.logger.info('OFPHello received:\n\tOF version=0x%02x %s %s' % (msg.version, msg.datapath.id, msg.datapath.address) )


	@set_ev_cls(ofp_event.EventOFPErrorMsg,[HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
	def error_msg_handler(self, ev):
		msg = ev.msg
		self.printme('OFPErrorMsg received:\n\ttype=0x%02x code=0x%02x message=%s\n\n' % (msg.type, msg.code, hex_array(msg.data)), msg.datapath )


	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto
		ofp_parser = dp.ofproto_parser	

		if msg.reason == ofp.OFPR_NO_MATCH:
			reason = 'NO MATCH'	
		elif msg.reason == ofp.OFPR_ACTION:
			reason = 'ACTION'
		elif msg.reason == ofp.OFPR_INVALID_TTL:
			reason = 'INVALID TTL'
		else:
			reason = 'unknown'

		self.printme("Packet In:", dp, 0)
		
		#print vars(msg)
		field = []
		for f in msg.match.fields:
			field.append('%s: value=%s' % (f.__class__.__name__, f.value))
			if (f.__class__.__name__ == 'MTInPort'):
				in_port = f.value
			#elif (f.__class__.__name__ == 'MTInPhyPort'):
				#in_port_phy = f.value
			else:
				print '%s: value=%s' % (f.__class__.__name__, f.value)
		
		self.printme ("REASON=%s (%x) IN_PORT=%s IN_PORT_PHY=%s" % (reason, msg.reason, f.value, f.value), 0, 1)
		
		pkt = packet.Packet( msg.data )
		for p in pkt:
			try:
				protocol_name = p.protocol_name
			except AttributeError:
				#print 'No Attribs'
				protocol_name = None
			#else:
				#print protocol_name, p

			if (protocol_name == "ethernet"):
				#print (vars(p))
				src = p.src
				dst = p.dst
				ethertype = p.ethertype
				#WOrkaround for instance mode, could be handled much better
				v_ethertype = p.ethertype
				vid = 0

			if (protocol_name == "vlan"):
				#print (vars(p))
				vid = p.vid
				v_ethertype = p.ethertype
				#print hex(vid)
				#print hex(v_ethertype)

			if (protocol_name == "ipv4"):	
				#print (vars(p))
				ipsrc = p.src
				ipdst = p.dst
				nw_proto = p.proto
				protocol_name = p.protocol_name
				#print socket.inet_ntoa(struct.pack('!I', p.src))
				#print socket.inet_ntoa(struct.pack('!I', p.dst))

			if (protocol_name == "ipv6"):	
				print (vars(p))
				ipsrc = p.src
				ipdst = p.dst
				nw_proto = 0x86DD
				protocol_name = p.protocol_name
				#print socket.inet_ntoa(struct.pack('!I', p.src))
				#print socket.inet_ntoa(struct.pack('!I', p.dst))

			if (protocol_name == "arp"):
				print (vars(p))
				a_proto = p.proto
				protocol_name = p.protocol_name
				a_ipsrc = p.src_ip
				a_ipdst = p.dst_ip
				#print proto
				#print protocol_name

			if (protocol_name == "icmp"):
				print (vars(p))
				print "do something special with ICMP flows?"

			if (protocol_name == "lldp"):
				#print (vars(p))
				for tlv in p.tlvs: 
					#if (tlv.__class__.__name__ == "SystemName"):
					#	print "System Name: %s" % (tlv.tlv_info)	
					#elif (tlv.__class__.__name__ == "ChassisID"):
					#	print "Chassis ID: %s" % (hex_array(tlv.tlv_info))
						#(socket.inet_ntoa(struct.pack('!BBBB', tlv.tlv_info[0], tlv.tlv_info[1], tlv.tlv_info[2], tlv.tlv_info[3] )
					#elif (tlv.__class__.__name__ == "PortID"):
					#	print "Port: %s" % (tlv.tlv_info)	
					if (tlv.__class__.__name__ == "PortDescription"):
					#	print "Port Descr: %s" % (tlv.tlv_info)
						pd = tlv.tlv_info
					#else:
					#	print "Unknown TLV"
					#print vars(tlv)
					#print '%s' % (tlv.__class__.__name__)
				#print "learn lldp neighbors on controller, make a webUI?"
				print "Datapath 0x%016x %010d Connected to %s" % (dp.id, in_port, pd)
				return

		self.printme("ETH=%s\tPORT=%s\tSRC=%s\tDST=%s" % (hex(ethertype), in_port , src, dst), dp, 1)
		#self.printme("IP_SRC=%s\tIP_DSST=%s\tVLAN=0x%x" % (socket.inet_ntoa(struct.pack('!I', ipdst)), socket.inet_ntoa(struct.pack('!I', ipsrc)), vid) )
		#print "ETHER=0x%x V_ETHER=0x%x" % (ethertype, v_ethertype)	
		self.mac_to_port[dp][src] = in_port

		#ugly arp handling
		if (v_ethertype == 0x806):
			if dst in self.mac_to_port[dp]:
				out_port = self.mac_to_port[dp][dst]
			else:
				out_port = ofp.OFPP_NORMAL

			self.send_packet_out(msg.datapath, 0xffffffff, in_port, ev.msg.data, out_port)
			match = ofp_parser.OFPMatch()
			match.set_dl_type(v_ethertype)
			match.set_in_port(in_port)
			match.set_vlan_vid(vid)
			actions = [ofp_parser.OFPActionOutput(out_port, 0)]
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
			cookie = in_port ^ dp.id ^ out_port
			#self.send_flow_mod(msg.datapath, match, actions, inst, 10, 0, cookie)		
			return

		if (v_ethertype == 0x86DD):
			if dst in self.mac_to_port[dp]:
				out_port = self.mac_to_port[dp][dst]
			else:
				out_port = ofp.OFPP_FLOOD

			self.send_packet_out(msg.datapath, 0xffffffff, in_port, ev.msg.data, out_port)

			match = ofp_parser.OFPMatch()
			match.set_dl_type(v_ethertype)
			print "IP src/dst"
			#print "".join("{0:x}".format(ord(c)) for c in ipsrc)
			#print ':'.join(hex(ord(x))[2:] for x in ipdst)
			match.set_ipv6_src(self.ipv6convert(ipsrc))
			match.set_ipv6_dst(self.ipv6convert(ipdst))
			match.set_in_port(in_port)
			match.set_vlan_vid(vid)
			actions = [ofp_parser.OFPActionOutput(out_port, 0)]
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

			if (out_port == ofp.OFPP_FLOOD):
				hardtime = 60
				idletime = 30
			else:
				hardtime = 0
				idletime = 60

			cookie = in_port ^ dp.id ^ out_port
			self.send_flow_mod(msg.datapath, match, actions, inst, hardtime, idletime, cookie)		
			return	
		
		if (v_ethertype == 0x800):
			if dst in self.mac_to_port[dp]:
				out_port = self.mac_to_port[dp][dst]
			else:
				out_port = ofp.OFPP_FLOOD

			self.send_packet_out(msg.datapath, 0xffffffff, in_port, ev.msg.data, out_port)

			match = ofp_parser.OFPMatch()
			match.set_dl_type(v_ethertype)
			match.set_ipv4_src(ipsrc)
			match.set_ipv4_dst(ipdst)
			#match.set_dl_src(src)
			#match.set_dl_dst(dst)			
			match.set_in_port(in_port)
			match.set_vlan_vid(vid)

			actions = [ofp_parser.OFPActionOutput(out_port, 0)]
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

			if (out_port == ofp.OFPP_FLOOD):
				hardtime = 60
				idletime = 30
			else:
				hardtime = 0
				idletime = 60

			cookie = ipsrc ^ in_port ^ dp.id ^ out_port

			self.send_flow_mod(msg.datapath, match, actions, inst, hardtime, idletime, cookie)
		else:
			self.printme("UNKNOWN ETH TYPE [0x%04x], IGNORING PACKET" % (v_ethertype), msg.datapath, 0)


	@set_ev_cls(ofp_event.EventOFPStateChange, [handler.MAIN_DISPATCHER, handler.DEAD_DISPATCHER])
	def dispacher_change(self, ev):
		datapath = ev.datapath
		assert datapath is not None

		if ev.state == handler.MAIN_DISPATCHER:
			self.printme("Client Connected:", datapath )
			self.clientConnected(datapath)
		elif ev.state == handler.DEAD_DISPATCHER:
			self.printme("Client Disconnect") 
			self.logger.info("[0x%016x] %s: Client Disconnect", datapath.id, datapath.address)
		else:
			print "\nOTHER STATE\n"


        @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
        def flow_removed_handler(self, ev):
		msg = ev.msg
		dp = msg.datapath
		ofp = dp.ofproto

		if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
			reason = 'IDLE TIMEOUT'
		elif msg.reason == ofp.OFPRR_HARD_TIMEOUT:
			reason = 'HARD TIMEOUT'
		elif msg.reason == ofp.OFPRR_DELETE:
			reason = 'DELETE'
		elif msg.reason == ofp.OFPRR_GROUP_DELETE:
			reason = 'GROUP DELETE'			
		else:
			reason = 'unknown'


		self.printme('OFPFlowRemoved received', dp, 0)
		self.printme('tableID=%d cookie=%d priority=%d\n\treason=%s duration_sec=%d duration_nsec=%d idle_timeout=%d packet_count=%d byte_count=%d' 
			% (msg.table_id, msg.cookie, msg.priority, reason, msg.duration_sec, msg.duration_nsec, msg.idle_timeout, msg.packet_count, msg.byte_count), 0, 1)


	def send_aggregate_stats_request(self, datapath):
		self.printme("SENT aggregate_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPAggregateStatsRequest(datapath=datapath, flags=0, table_id=ofp.OFPTT_ALL,out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,cookie=0, cookie_mask=0,match=ofp_parser.OFPMatch())
		datapath.send_msg(req)


	def send_get_async_request(self, datapath):
		self.printme("SENT get_async_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPGetAsyncRequest(datapath)
		datapath.send_msg(req)


	def send_barrier_request(self, datapath):
		self.printme("SENT barrier_request", datapath, 3)
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPBarrierRequest(datapath)
		datapath.send_msg(req)


	def send_echo_reply(self, datapath, data):
		self.printme("SENT echo_reply", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		reply = ofp_parser.OFPEchoReply(datapath)
		reply.data = data
		datapath.send_msg(reply)


	def send_echo_request(self, datapath, data):
		self.printme("SENT echo_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPEchoRequest(datapath)
		req.data = data
		datapath.send_msg(req)	


	def send_group_mod(self, datapath, group_id, command):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
		buckets = [ofp_parser.OFPBucket(len_=0, weight=1, watch_port=ofp.OFPP_ANY, watch_group=ofp.OFPG_ANY, actions=actions)]
		buckets += [ofp_parser.OFPBucket(len_=0, weight=1, watch_port=ofp.OFPP_ANY, watch_group=ofp.OFPG_ANY, actions=actions)]
		req = ofp_parser.OFPGroupMod(datapath=datapath, command=command, type_=ofp.OFPGT_SELECT, group_id=group_id,buckets=buckets)
		datapath.send_msg(req)


	def send_delete_all_group_mod(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		#actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
		#buckets = [ofp_parser.OFPBucket(len_=0, weight=1, watch_port=ofp.OFPP_ANY, watch_group=ofp.OFPG_ANY, actions=actions)]
		actions = []
		buckets = []
		
		#req = ofp_parser.OFPGroupMod(datapath=datapath, command=ofp.OFPFC_DELETE, type_=ofp.OFPGT_ALL, group_id=ofp.OFPG_ANY,buckets=buckets)
		#datapath.send_msg(req)

		req = ofp_parser.OFPGroupMod(datapath=datapath, command=ofp.OFPFC_DELETE, type_=ofp.OFPGT_SELECT, group_id=ofp.OFPG_ANY,buckets=buckets)
		datapath.send_msg(req)		


	def send_flow_stats_request(self, datapath):
		self.printme("SENT flow_stats", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPFlowStatsRequest(datapath=datapath, flags=0, table_id=ofp.OFPTT_ALL, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, cookie=0, cookie_mask=0, match=ofp_parser.OFPMatch())
		datapath.send_msg(req)


	def send_get_config_request(self, datapath):
		self.printme("SENT get_config", datapath, 3)
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPGetConfigRequest(datapath)
		datapath.send_msg(req)


	def send_features_request(self, datapath):
		self.printme("SENT features_request", datapath, 3)
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPFeaturesRequest(datapath)
		datapath.send_msg(req)


	def send_raw_packet_out(self, datapath, buffer_id, in_port):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		actions = [ofp_parser.OFPActionOutput(ofp.OFPP_FLOOD, 0)]
		req = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,in_port=in_port, actions=actions, data="RAWRAWRAWRAW\x14")
		datapath.send_msg(req)	


	def send_packet_out(self, datapath, buffer_id, in_port, data, out_port):
		self.printme("SENT packet_out", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		actions = [ofp_parser.OFPActionOutput(out_port, 0)]
		#actions = [ofp_parser.OFPInstructionGotoTable(200)]
		req = ofp_parser.OFPPacketOut(datapath=datapath, buffer_id=buffer_id,in_port=in_port, actions=actions, data=data)
		self.printme("PACKET OUT:", datapath, 0)
		self.printme("OUT_PORT=%s" % (out_port), 0, 1)
		datapath.send_msg(req)		


	def send_port_desc_stats_request(self, datapath):
		self.printme("SENT port_desc_stats_request", datapath, 3)
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortDescStatsRequest(datapath, 0)
		datapath.send_msg(req)


	def send_port_stats_request(self, datapath):
		self.printme("SENT port_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPPortStatsRequest(datapath, 0, ofp.OFPP_ANY)
		datapath.send_msg(req)


	def send_role_request(self, datapath):
		self.printme("SENT role_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPRoleRequest(datapath, ofp.OFPCR_ROLE_MASTER, 0)
		datapath.send_msg(req)	


	def send_set_config(self, datapath):
		self.printme("SENT set_config", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 1518)
		datapath.send_msg(req)


	def send_test_ip_flow_mod(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser	
		match = ofp_parser.OFPMatch()	
		#match.set_dl_src("\x00\x07\x13\x00\x00\x01")
		#match.set_dl_dst("\x00\x07\x16\x00\x00\x01")		
		match.set_dl_type(0x800)		
		match.set_ipv4_src_masked(ipv4_to_bin("143.143.143.100"), ipv4_to_bin("255.255.255.255"))
		match.set_ipv4_dst_masked(ipv4_to_bin("143.143.143.1"), ipv4_to_bin("255.255.255.255"))
		#match.set_ipv4_dst_masked(2408550344, 4294967040)		
		#match.set_ipv4_src(2408550244)
		#match.set_ipv4_dst(2408550344)
		#match.set_in_port(1)
		match.set_vlan_vid(0x001)
		
		#actions = [ofp_parser.OFPActionOutput(1, 0)]
		inst = [ofp_parser.OFPInstructionGotoTable(101)]
		#inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		req = ofp_parser.OFPFlowMod(datapath=datapath,
			cookie=0x01, cookie_mask=0,
			table_id=50, command=ofp.OFPFC_ADD,
			idle_timeout=0, hard_timeout=0,
			priority=32768,
			buffer_id=0xffffffff,
			out_port=ofp.OFPP_ANY,
			out_group=ofp.OFPG_ANY,
			flags=ofp.OFPFF_SEND_FLOW_REM,
			match=match, instructions=inst)
		#print vars(req)
		datapath.send_msg(req)	
		
		
		match = ofp_parser.OFPMatch()	
		#match.set_dl_src("\x00\x07\x13\x00\x00\x01")
		#match.set_dl_dst("\x00\x07\x16\x00\x00\x01")		
		match.set_dl_type(0x800)		
		match.set_ipv4_src_masked(ipv4_to_bin("143.143.143.200"), ipv4_to_bin("255.255.255.255"))
		match.set_ipv4_dst_masked(ipv4_to_bin("143.143.143.0"), ipv4_to_bin("255.255.255.0"))
		#match.set_ipv4_dst_masked(2408550344, 4294967040)		
		#match.set_ipv4_src(2408550244)
		#match.set_ipv4_dst(2408550344)
		#match.set_in_port(1)
		match.set_vlan_vid(0x001)
		
		#actions = [ofp_parser.OFPActionOutput(1, 0)]
		inst = [ofp_parser.OFPInstructionGotoTable(101)]
		#inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
		req = ofp_parser.OFPFlowMod(datapath=datapath,
			cookie=0x01, cookie_mask=0,
			table_id=50, command=ofp.OFPFC_ADD,
			idle_timeout=0, hard_timeout=0,
			priority=32768,
			buffer_id=0xffffffff,
			out_port=ofp.OFPP_ANY,
			out_group=ofp.OFPG_ANY,
			flags=ofp.OFPFF_SEND_FLOW_REM,
			match=match, instructions=inst)
		#print vars(req)
		datapath.send_msg(req)	
		
		
	def send_default_arp_mod(self, datapath, vlans):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser	
		self.printme("ADD DEFAULT ARP FLOWS:", datapath)
		for vlan in vlans:
			match = ofp_parser.OFPMatch()
			match.set_dl_type(0x806)
			match.set_vlan_vid(vlan)
			self.printme("TableID=100 ACTION=['output', 'NORMAL'] VLAN=%s" % (vlan))	
			actions = [ofp_parser.OFPActionOutput(ofp.OFPP_NORMAL, 0)]
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]				
			req = ofp_parser.OFPFlowMod(datapath=datapath,
				cookie=0x01, cookie_mask=0, table_id=100, command=ofp.OFPFC_ADD,
				idle_timeout=0, hard_timeout=0, priority=32768, buffer_id=0xffffffff,
				out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_SEND_FLOW_REM,
				match=match, instructions=inst)
			#print vars(req)
			datapath.send_msg(req)		


	def send_default_flow_mod(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser	
		self.printme("ADD TABLE-MISS FLOWS:", datapath)
		for table in self.tables:
			match = ofp_parser.OFPMatch()
			#if (table == 50):
				#match.set_dl_type(0x800)

			self.printme("TableID=%s ACTION=%s" % (table, self.tables[table]))	
			if self.tables[table][0] == "goto":
				inst = [ofp_parser.OFPInstructionGotoTable(self.tables[table][1])]
			elif self.tables[table][0] == "output":
				actions = [ofp_parser.OFPActionOutput(self.tables[table][1], 0)]
				inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]				
			else:
				print "ERROR CREATING DEFAULT FLOWS"
				sys.exit(0)

			req = ofp_parser.OFPFlowMod(datapath=datapath,
				cookie=0x01, cookie_mask=0, table_id=table, command=ofp.OFPFC_ADD,
				idle_timeout=0, hard_timeout=0, priority=0, buffer_id=0xffffffff,
				out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY, flags=ofp.OFPFF_SEND_FLOW_REM,
				match=match, instructions=inst)
			#print vars(req)
			datapath.send_msg(req)		


	def send_delete_all_flow_mod(self, datapath):
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		self.printme("DELETE ALL FLOWS:", datapath)
		for table in self.tables:
			self.printme("TableID=%s" % (table))
			match = ofp_parser.OFPMatch()	
			actions = [ofp_parser.OFPActionOutput(ofp.OFPP_ALL, 0)]
			inst = [ofp_parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
			req = ofp_parser.OFPFlowMod(datapath=datapath, cookie=0x0, cookie_mask=0,
				table_id=table, command=ofp.OFPFC_DELETE, idle_timeout=0, hard_timeout=0,
				priority=0, buffer_id=0xffffffff, out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
				flags=ofp.OFPFF_SEND_FLOW_REM, match=match, instructions=inst)
			datapath.send_msg(req)


	def send_flow_mod(self, datapath, match, actions, inst, hardtime, idletime, cookie):
		self.printme("ADD FLOW:", datapath)
		if self.ipControlTableMode:
			tableID = 50
		else:
			tableID = 100

		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPFlowMod(datapath=datapath,
			cookie=cookie, cookie_mask=0,
			table_id=tableID, command=ofp.OFPFC_ADD,
			idle_timeout=idletime, hard_timeout=hardtime,
			priority=32768,
			buffer_id=0xffffffff,
			out_port=ofp.OFPP_ANY,
			out_group=ofp.OFPG_ANY,
			flags=ofp.OFPFF_SEND_FLOW_REM,
			match=match, instructions=inst)
		datapath.send_msg(req)


	def send_table_mod(self, datapath):
		self.printme("SENT tabled_mod", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPTableMod(datapath, 1, 3)
		datapath.send_msg(req)


	def send_group_stats_request(self, datapath):
		self.printme("SENT group_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPGroupStatsRequest(datapath, 0, ofp.OFPG_ALL)
		datapath.send_msg(req)


	def send_group_features_stats_request(self, datapath):
		self.printme("SENT group_features_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPGroupFeaturesStatsRequest(datapath, 0)
		datapath.send_msg(req)


	def send_table_features_stats_request(self, datapath):
		self.printme("SENT table_features_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPTableFeaturesStatsRequest(datapath, 0, [], 0)
		datapath.send_msg(req)


	def send_table_stats_request(self, datapath):
		self.printme("SENT table_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPTableStatsRequest(datapath, 0)
		datapath.send_msg(req)


	def send_meter_features_stats_request(self, datapath):
		self.printme("SENT meter_features_stats_request", datapath, 3)
		ofp = datapath.ofproto
		ofp_parser = datapath.ofproto_parser
		req = ofp_parser.OFPMeterFeaturesStatsRequest(datapath, 0)
		datapath.send_msg(req)


	def show_flow_stats(self, body, dp):
		flows = []
		self.printme('FlowStats:', dp, 0)
		for stat in body:
			self.printme('length=%d table_id=%s '
				'duration_sec=%d duration_nsec=%d '
				'priority=%d '
				'idle_timeout=%d hard_timeout=%d flags=0x%04x '
				'cookie=%d packet_count=%d byte_count=%d '
				'match=%s' %
				(stat.length, stat.table_id,
				stat.duration_sec, stat.duration_nsec,
				stat.priority,
				stat.idle_timeout, stat.hard_timeout, stat.flags,
				stat.cookie, stat.packet_count, stat.byte_count,
				stat.match)
				, 0, 1)
			flows.append('length=%d table_id=%s '
				'duration_sec=%d duration_nsec=%d '
				'priority=%d '
				'idle_timeout=%d hard_timeout=%d flags=0x%04x '
				'cookie=%d packet_count=%d byte_count=%d '
				'match=%s' %
				(stat.length, stat.table_id,
				stat.duration_sec, stat.duration_nsec,
				stat.priority,
				stat.idle_timeout, stat.hard_timeout, stat.flags,
				stat.cookie, stat.packet_count, stat.byte_count,
				stat.match))


	def show_aggregate_stats(self, body, dp):
		aggregates = []
		for stat in body:
			aggregates.append('packet_count=%d byte_count=%d flow_count=%d' %
				(stat.packet_count, stat.byte_count, stat.flow_count))
		self.printme('AggregateStats:', dp, 0)
		self.printme('%s' % (aggregates), 0, 1)


	def show_port_stats(self, body, dp):
		ports = []
		self.printme('PortStats:', dp, 0)
		for stat in sorted(body):
			self.printme('port_no=%d rx_packets=%d tx_packets=%d rx_bytes=%d tx_bytes=%d rx_dropped=%d tx_dropped=%d rx_errors=%d tx_errors=%d rx_frame_err=%d rx_over_err=%d rx_crc_err=%d collisions=%d duration_sec=%d duration_nsec=%d' %
				(stat.port_no, stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes, stat.rx_dropped, stat.tx_dropped, stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err, stat.rx_crc_err, stat.collisions, stat.duration_sec, stat.duration_nsec), 0, 1)
			#ports.append('port_no=%d rx_packets=%d tx_packets=%d rx_bytes=%d tx_bytes=%d rx_dropped=%d tx_dropped=%d rx_errors=%d tx_errors=%d rx_frame_err=%d rx_over_err=%d rx_crc_err=%d collisions=%d duration_sec=%d duration_nsec=%d' %
			#	(stat.port_no, stat.rx_packets, stat.tx_packets, stat.rx_bytes, stat.tx_bytes, stat.rx_dropped, stat.tx_dropped, stat.rx_errors, stat.tx_errors, stat.rx_frame_err, stat.rx_over_err, stat.rx_crc_err, stat.collisions, stat.duration_sec, stat.duration_nsec))
			
			
			#self.logger.info('Port: %05d', stat.port_no)


	def show_port_desc(self, body, dp):
		ports = []
		ofp = dp.ofproto
		#self.mac_to_port[datapath][struct.pack('BBBBBB', 255, 255, 255, 255, 255, 255)]=datapath.ofproto.OFPP_FLOOD
		self.printme("Port Desc:", dp, 0)
		for p in sorted(body):
			#print p
			ports.append('port_no=%d hw_addr=%s name=%s config=0x%08x state=0x%08x curr=0x%08x advertised=0x%08x supported=0x%08x curr_speed=%d max_speed=%d' %
				(p.port_no, p.hw_addr, p.name.rstrip(chr(0x00)).ljust(8, "-"), p.config, p.state, p.curr, p.advertised, p.supported, p.curr_speed, p.max_speed))

			star=" "
			if (p.state==0):
			#star = "*" if p.state==0 else " "
				star="*"
				if (self.sendLLDPDiscoveryFrames):
					self.sendLLDPPacket(dp, p.port_no, p.hw_addr)

			self.printme('%sPort: %010d\tState: 0x%08x\tName: %s\tMAC=%s' % (star, p.port_no, p.state, self.filter_non_printable(p.name.rstrip(chr(0x00)) + chr(0xff)).ljust(8, "-"), p.hw_addr ), 0, 1)

			if (p.port_no == ofp.OFPP_LOCAL):
				#self.printme("Learn MAC=%s on Port=NORMAL" % (haddr_to_str(p.hw_addr)))
				self.mac_to_port[dp][p.hw_addr]=dp.ofproto.OFPP_NORMAL	
		#self.printme('OFPPortDescStatsReply received:\n\t%s' % (ports), dp)				
		self.printme ("* indicates port is UP", 0, 1)


	def show_group_stats(self, body, dp):
		groups = []
		for stat in body:
			groups.append('length=%d group_id=%d '
				'ref_count=%d packet_count=%d byte_count=%d '
				'duration_sec=%d duration_nsec=%d' %
				(stat.length, stat.group_id,
				stat.ref_count, stat.packet_count, stat.byte_count,
				stat.duration_sec, stat.duration_nsec))
		self.printme('GroupStats:', dp, 0)
		self.printme('%s' % (groups), 0, 1)


	def show_group_features_stats(self, body, dp):
		features = []
		for stat in body:
			features.append('types=%d capabilities=0x%08x max_groups=%s actions=%s' %
				(stat.types, stat.capabilities, stat.max_groups, stat.actions))
	
		self.printme('GroupFeaturesStats:', dp, 0)
		self.printme('%s' % (features), 0, 1)


	def show_table_stats(self, body, dp):
		tables = []
		self.printme('TableStats:', dp, 0)
		for stat in body:
			self.printme('table_id=%d active_count=%d lookup_count=%d matched_count=%d' % (stat.table_id, stat.active_count, stat.lookup_count, stat.matched_count), 0, 1)
			#tables.append('table_id=%d active_count=%d lookup_count=%d matched_count=%d' % (stat.table_id, stat.active_count, stat.lookup_count, stat.matched_count))


	def table_features_stats(self, body, dp):
		self.printme("TableFeatureStats:", dp, 0)
		for stat in body:
			#print stat
			self.printme("Table=%03d Name=%s Max_Entries=%06d Match=0x%016x Write=0x%x " % (stat.table_id, stat.name, stat.max_entries, stat.metadata_match, stat.metadata_write), 0, 1)

	def show_meter_features_stats(self, body, dp):
		features = []
		for stat in body:
			features.append('max_meter=%d band_types=0x%08x capabilities=0x%08x max_band=%d max_color=%d' %
			(stat.max_meter, stat.band_types, stat.capabilities, stat.max_band, stat.max_color))
		self.printme('MeterFeaturesStats:', dp, 0 )
		self.printme('%s' % (features), 0, 1)


	def sendLLDPPacket(self, datapath, port, src):
		pkt = packet.Packet()
		dst = lldp.LLDP_MAC_NEAREST_BRIDGE
		ethertype = ether.ETH_TYPE_LLDP
		eth_pkt = ethernet.ethernet(dst, src, ethertype)
		pkt.add_protocol(eth_pkt)
		tlv_chassis_id = lldp.ChassisID(subtype=0x05, chassis_id='\x01\xff\xff\xff\xff')
		tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_INTERFACE_NAME, port_id='Port %010d' %(port))
		tlv_ttl = lldp.TTL(ttl=120)
		tlv_port_description = lldp.PortDescription(port_description='0x%016x %010d' % (datapath.id, port))
		tlv_system_name = lldp.SystemName(system_name='RYU %s' % (datapath.address[0]) )
		tlv_system_description = lldp.SystemDescription(system_description='RYU Controller')
		tlv_system_capabilities = lldp.SystemCapabilities(subtype=lldp.ChassisID.SUB_CHASSIS_COMPONENT, system_cap=0x14,enabled_cap=0x14)
		tlv_management_address = lldp.ManagementAddress(addr_subtype=0x01, addr='\xff\xff\xff\xff',intf_subtype=0x02, intf_num=0xffffffff,oid='')
		#tlv_organizationally_specific = lldp.OrganizationallySpecific(oui='\x00\x12\x0f', subtype=0x02, info='\x07\x01\x00')
		tlv_end = lldp.End()
		tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_port_description,tlv_system_name, tlv_system_description,tlv_system_capabilities, tlv_management_address, tlv_end)
		lldp_pkt = lldp.lldp(tlvs)
		pkt.add_protocol(lldp_pkt)
		pkt.serialize()

		self.send_packet_out(datapath, 0xffffffff, datapath.ofproto.OFPP_CONTROLLER, pkt.data, port)
