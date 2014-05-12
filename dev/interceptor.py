# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import array
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet.udp import udp
from ryu.lib import addrconv

CONTROLLER_IP = '192.168.100.1'
CONTROLLER_MAC = '5a:97:c4:9b:8e:43'
CONTROLLER_SPECIAL_MAC = 'be:ef:be:ef:be:ef'
CONTROLLER_SPECIAL_IP = '192.168.100.2'
DHCP_SERVER_IP = '192.168.100.3'
DHCP_SERVER_MAC = 'de:ad:be:ef:ba:be'
DHCP_SERVER_OUT_PORT = -1
DHCP_SERVER_DISCOVERED = False



class Interceptor(app_manager.RyuApp):
    
    
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    
    def __init__(self, *args, **kwargs):
        super(Interceptor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

  
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_enter_handler(self, ev):
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("Switch entered: %s", dp.id)
            self.bindToDHCPServer(dp,ofproto,parser)
        
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            self.logger.info("Switch left: %s", dp.id)

    
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    
    def bindToDHCPServer(self, datapath, ofproto, parser):
        ##arp for the DHCP server first, to learn its out port
        ##form the ARP req
        a_hwtype = 1
        a_proto = ether.ETH_TYPE_IP
        a_hlen = 6
        a_plen = 4
        a_opcode = 1 #request1
        a_srcMAC = CONTROLLER_SPECIAL_MAC
        a_srcIP = CONTROLLER_SPECIAL_IP
        a_dstMAC = DHCP_SERVER_MAC
        a_dstIP = DHCP_SERVER_IP
        
        p = packet.Packet()
        e = ethernet.ethernet(DHCP_SERVER_MAC,CONTROLLER_SPECIAL_MAC,ether.ETH_TYPE_ARP)
        a = arp.arp(a_hwtype,a_proto,a_hlen,a_plen,a_opcode,a_srcMAC,a_srcIP,a_dstMAC,a_dstIP)
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        
        #send packet out
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
                                      in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
        datapath.send_msg(out)
        dpid = datapath.id
        self.logger.info("packet out dpid:'%s' src:'%s' dst:'%s' out_port:'OFPP_FLOOD'", dpid, CONTROLLER_SPECIAL_MAC, DHCP_SERVER_MAC)
        self.logger.info("[ADMIN] Attempting to discover DHCP server... ")
    
    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        #print protocols
        return protocols
    
    def detect_dhcp_discover(self, pkt):
        protocols = self.get_protocols(pkt)
        
        try:
			#find the encapsulated ip data inside the packet
			ipv4 = protocols['ipv4']
			if ipv4:
				if ipv4.proto == inet.IPPROTO_UDP:
					#self.logger.info("packet is of type udp, let's try to deassemble it")
					u = protocols['udp']
					#self.logger.info("packet contains udp src port of '%s' and udp dst port of '%s'", u.src_port, u.dst_port)
					#self.logger.info("packet ip addressing is src: '%s' dst: '%s'", ipv4.src, ipv4.dst)
					if u.src_port == 68 and u.dst_port == 67 and ipv4.dst == '255.255.255.255':
						#self.logger.info("packet likely contains a dhcp discover!")
						return True
			else:
				return False
        except Exception:
            return False
    
    def detect_dhcp_offer(self,pkt):
		protocols = self.get_protocols(pkt)
		
		try:
			ipv4 = protocols['ipv4']
			if ipv4:
				if ipv4.proto == inet.IPPROTO_UDP:
					u = protocols['udp']
					if u.src_port == 67 and u.dst_port == 68 and ipv4.dst == '255.255.255.255.':
						return True
		except Exception:
			return False
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global DHCP_SERVER_OUT_PORT
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
    
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.logger.info("packet in dpid:'%s' src:'%s' dst:'%s' in_port:'%s'", dpid, eth.src, eth.dst, in_port)
        
        # detailed packet
        d_pkt = packet.Packet(array.array('B', msg.data))
        dhcp_d = self.detect_dhcp_discover(d_pkt)
        dhcp_o = self.detect_dhcp_offer(d_pkt)
        
        if eth.src == DHCP_SERVER_MAC and !DHCP_SERVER_DISCOVERED:
            DHCP_SERVER_OUT_PORT = in_port
            self.logge.info("[ADMIN] Discovered the local DHCP server source port on local bridge -> port %s",DHCP_SERVER_OUT_PORT)
            DHCP_SERVER_DISCOVERED = True
        
        if dhcp_d and DHCP_SERVER_DISCOVERED:
            self.logger.info("[ADMIN] [DHCPD] DHCP Discover came in from client source MAC: '%s'", eth.src)
            ##create a flow between requester and dhcp server
            
            # learn a mac address to avoid flood etc
            self.mac_to_port[dpid][eth.src] = in_port
            
            #out_port = self.mac_to_port[dpid][DHCP_SERVER_MAC]
            #print("DHCP_SERVER_OUT_PORT = '%d'",DHCP_SERVER_OUT_PORT)
            actions = [parser.OFPActionOutput(DHCP_SERVER_OUT_PORT)]
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, out_port=DHCP_SERVER_OUT_PORT, eth_dst=DHCP_SERVER_MAC)
            self.add_flow(datapath, 1, match, actions)
            
            data = None
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        
        if dhcp_o:
            self.logger.info("[ADMIN] [DHCPO] DHCP Offer sent from DHCP server to client destination MAC: '%s'", eth.dst)
        
        #dhcp_o
        #dhcp_r
        #dhcp_a

