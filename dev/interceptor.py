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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib.packet.udp import udp
from ryu.lib import addrconv

DHCP_SERVER_IP = '192.168.100.2'
#DHCP_SERVER_MAC = 'DE:AD:BE:EF:BA:BE'
DHCP_SERVER_MAC = 'de:ad:be:ef:ba:be'

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

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        print protocols
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
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
        dhcp_d = self.detect_dhcp_discover(d_pkt);
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][eth.src] = in_port
        
        if eth.dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][eth.dst]
        else:
            if eth.dst != DHCP_SERVER_MAC:
                out_port = ofproto.OFPP_FLOOD
        
        
        if dhcp_d:
            self.logger.info("dhcp discover came in from client src mac: '%s'", eth.src)
            ##create a flow between requester and dhcp server
            out_port = self.mac_to_port[dpid][eth.dst]
            actions = [parser.OFPActionOutput(out_port)]
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=DHCP_SERVER_MAC)
            self.add_flow(datapath, 1, match, actions)
        #dhcp_o
        #dhcp_r
        #dhcp_a
        if eth.dst != DHCP_SERVER_MAC:
            actions = [parser.OFPActionOutput(out_port)]

        

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD and eth.dst != DHCP_SERVER_MAC:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
