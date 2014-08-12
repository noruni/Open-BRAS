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

import ConfigParser

import struct
import re

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

class Interceptor(app_manager.RyuApp):

    def __init__(self, *args, **kwargs):
        super(Interceptor, self).__init__(*args, **kwargs)
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Interceptor) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        #get information about how this controller has been configured
        self.CONTROLLER_IP = config.get('global', 'CONTROLLER_IP')
        self.CONTROLLER_MAC = config.get('global', 'CONTROLLER_MAC')
        self.CONTROLLER_SPECIAL_IP = config.get('global', 'CONTROLLER_SPECIAL_IP')
        self.CONTROLLER_SPECIAL_MAC = config.get('global', 'CONTROLLER_SPECIAL_MAC')
        #get information about known AAA services
        self.DHCP_SERVER_IP = config.get('aaa', 'DHCP_SERVER_IP')
        self.DHCP_SERVER_MAC = config.get('aaa', 'DHCP_SERVER_MAC')


    def discover_dhcp_server(self, datapath, ofproto, parser):
        ##arp for the DHCP server first, to learn its out port
        ##form the ARP req
        a_hwtype = 1
        a_proto = ether.ETH_TYPE_IP
        a_hlen = 6
        a_plen = 4
        a_opcode = 1 #request1
        a_srcMAC = self.CONTROLLER_SPECIAL_MAC
        a_srcIP = self.CONTROLLER_SPECIAL_IP
        a_dstMAC = self.DHCP_SERVER_MAC
        a_dstIP = self.DHCP_SERVER_IP
        p = packet.Packet()
        e = ethernet.ethernet(a_dstMAC,a_srcMAC,ether.ETH_TYPE_ARP)
        a = arp.arp(a_hwtype,a_proto,a_hlen,a_plen,a_opcode,a_srcMAC,a_srcIP,a_dstMAC,a_dstIP)
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        #send packet out
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p.data)
        datapath.send_msg(out)
        dpid = datapath.id
        self.logger.info("packet out dpid:'%s' src:'%s' dst:'%s' out_port:'OFPP_FLOOD'", dpid, self.CONTROLLER_SPECIAL_MAC, self.DHCP_SERVER_MAC)
        self.logger.info("[ADMIN] Attempting to discover DHCP server... ")
        
        
    def get_protocols(self, pkt):
        protocols = {}
        for p in pkt:
            if hasattr(p, 'protocol_name'):
                protocols[p.protocol_name] = p
            else:
                protocols['payload'] = p
        return protocols


    def extract_options(self, pkt):
        protocols = self.get_protocols(pkt)
        payload = protocols['payload']
        dh = dhcp.dhcp.parser(str(payload))[0]
        dh_options = dh.options.option_list
        options = {}
        for option in dh_options:
            opt_length = option.length
            unpack_str = '%ds' % opt_length
            opt_val = struct.unpack_from(unpack_str,option.value)
            ##disgusting code to extract hex value from buffer
            ##1 byte only at the moment
            if opt_length == 1:
                regex = re.compile(r"\\")
                opt_val = regex.sub('0',str(opt_val))
                opt_val = opt_val[2:]
                opt_val = opt_val[:-3]
                opt_val = int(opt_val, 16)
                options[option.tag] = opt_val
        return options        


    def detect_dhcp_discover(self, pkt):
        protocols = self.get_protocols(pkt)
        try:
            #find the encapsulated ip data inside the packet
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 68 and u.dst_port == 67 and ipv4.dst == '255.255.255.255':
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 1:
                            return True
            else:
                return False
        except Exception as e:
            return False


    def detect_dhcp_offer(self,pkt):
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 67 and u.dst_port == 68 and ipv4.src == self.DHCP_SERVER_IP:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 2:
                            return True
            else:
                return False
        except Exception as e:
            return False
            
            
    def detect_dhcp_request(self, pkt):
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 68 and u.dst_port == 67:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 3:
                            return True
            else:
                return False
        except Exception as e:
            return False
          
            
    def detect_dhcp_ack(self, pkt): 
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 67 and u.dst_port == 68 and ipv4.src == self.DHCP_SERVER_IP:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 5:
                            return True
            else:
                return False
        except Exception as e:
            return False

    def detect_dhcp_nak(self, pkt):
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 67 and u.dst_port == 68 and ipv4.src == self.DHCP_SERVER_IP:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 6:
                            return True
            else:
                return False
        except Exception as e:
            return False
            
            
    def detect_dhcp_decline(self, pkt):
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 68 and u.dst_port == 67:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 4:
                            return True
            else:
                return False
        except Exception as e:
            return False
            
            
    def detect_dhcp_release(self, pkt):
        protocols = self.get_protocols(pkt)
        try:
            ipv4 = protocols['ipv4']
            if ipv4:
                if ipv4.proto == inet.IPPROTO_UDP:
                    u = protocols['udp']
                    if u.src_port == 68 and u.dst_port == 67:
                        options = self.extract_options(pkt)
                        if 53 in options and options[53] == 7:
                            return True
            else:
                return False
        except Exception as e:
            return False