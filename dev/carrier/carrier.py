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
import ConfigParser
import interceptor

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
from ryu.lib.packet.dhcp import options
from ryu.lib.packet.udp import udp
from ryu.lib import addrconv

DHCP_SERVER_OUT_PORT = -1
DHCP_SERVER_DISCOVERED = False

class Carrier(app_manager.RyuApp):
        
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    global i
    i = interceptor.Interceptor()

    def __init__(self, *args, **kwargs):
        super(Carrier, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        
        
        #get information about how this controller has been configured
        self.CONTROLLER_IP = config.get('global', 'CONTROLLER_IP')
        self.CONTROLLER_MAC = config.get('global', 'CONTROLLER_MAC')
        self.CONTROLLER_SPECIAL_IP = config.get('global', 'CONTROLLER_SPECIAL_IP')
        self.CONTROLLER_SPECIAL_MAC = config.get('global', 'CONTROLLER_SPECIAL_MAC')
        
        #get information about known AAA services
        self.DHCP_SERVER_IP = config.get('aaa', 'DHCP_SERVER_IP')
        self.DHCP_SERVER_MAC = config.get('aaa', 'DHCP_SERVER_MAC')
        
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        self.logger.info("[ADMIN] switch_features_handler(self, ev)")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 1, match, actions)

  
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def switch_enter_handler(self, ev):
        self.logger.info("[ADMIN] switch_enter_handler(self, ev)")
        dp = ev.datapath
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        if ev.state == MAIN_DISPATCHER:
            self.logger.info("Switch entered: %s", dp.id)
            i.discover_dhcp_server(dp,ofproto,parser)
            
        
        elif ev.state == DEAD_DISPATCHER:
            if dp.id is None:
                return
            self.logger.info("Switch left: %s", dp.id)

    
    def add_flow(self, datapath, priority, match, actions):
        self.logger.info("[ADMIN] add_flow(self, datapath, priority, match, actions)")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        global DHCP_SERVER_OUT_PORT
        global DHCP_SERVER_DISCOVERED
        

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
    
        
        pkt = packet.Packet(msg.data)
        protocols = i.get_protocols(pkt)

        #eth = pkt.get_protocols(ethernet.ethernet)[0]
        eth = protocols['ethernet']
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        
        self.logger.info("packet in dpid:'%s' src:'%s' dst:'%s' in_port:'%s'", dpid, eth.src, eth.dst, in_port)
        
        # detailed packet
        d_pkt = packet.Packet(array.array('B', msg.data))

        
        dhcp_d = i.detect_dhcp_discover(pkt)
        dhcp_o = i.detect_dhcp_offer(pkt)
        dhcp_r = i.detect_dhcp_request(pkt)
        dhcp_a = i.detect_dhcp_reply(pkt)
        
        if eth.src == self.DHCP_SERVER_MAC and not DHCP_SERVER_DISCOVERED:
            DHCP_SERVER_OUT_PORT = in_port
            self.logger.info("[ADMIN] Discovered the local DHCP server source port on local bridge -> port %s",DHCP_SERVER_OUT_PORT)
            DHCP_SERVER_DISCOVERED = True
        
        if dhcp_d and DHCP_SERVER_DISCOVERED:
            self.logger.info("[ADMIN] [DHCPD] DHCP Discover came in from client source MAC: '%s'", eth.src)
            ##create a flow between requester and dhcp server
            
            payload = protocols['payload']
            dh = dhcp.dhcp.parser(str(payload))[0]
            dh_options = dh.options.option_list
            #print dh_options
            for option in dh_options:
                print option #option(length=1,tag=53,value='\x01')
                print option.length #1
                print option.tag #53
                opt_length = option.length
                #opt_val = struct.unpack_from(('%s'%opt_length),option.value)[0]
                print "The len option.value is " + str(len(option.value))


                #        print opt_val
                                
                #        tag = struct.unpack_from(cls._UNPACK_STR, buf)[0]
                #        if tag == DHCP_END_OPT or tag == DHCP_PAD_OPT:
                #            return None
                #        buf = buf[cls._MIN_LEN:]
                #        length = struct.unpack_from(cls._UNPACK_STR, buf)[0]
                #        buf = buf[cls._MIN_LEN:]
                #        value_unpack_str = '%ds' % length
                #        value = struct.unpack_from(value_unpack_str, buf)[0]
                #        
                #        IndexError: tuple index out of range

                
                
            
            
            # learn a mac address to avoid flood etc
            self.mac_to_port[dpid][eth.src] = in_port
            
            #out_port = self.mac_to_port[dpid][DHCP_SERVER_MAC]
            #print("DHCP_SERVER_OUT_PORT = '%d'",DHCP_SERVER_OUT_PORT)
            actions = [parser.OFPActionOutput(DHCP_SERVER_OUT_PORT)]
            match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst='ff:ff:ff:ff:ff:ff')
            self.add_flow(datapath, 1, match, actions)
            
            data = None
                       
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            self.logger.info("packet out dpid:'%s' in_port:'%s'", datapath.id, in_port)
            datapath.send_msg(out)
        
        if dhcp_o and DHCP_SERVER_DISCOVERED:
            protocols = i.get_protocols(pkt) 
            ipv4 = protocols['ipv4']
            self.logger.info("[ADMIN] [DHCPO] DHCP Offer of '%s' sent from DHCP server to client destination MAC: '%s'", ipv4.dst, eth.dst)
            

            
            #debug code to make sure offer reaches the recipient host
            if eth.dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][eth.dst]
            else:
                out_port = ofproto.OFPP_FLOOD


            actions = [parser.OFPActionOutput(out_port)]

            data = None
            
            
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data
                
            if msg.buffer_id == -1:
                print "apparently we have a local copy of this packet?"
            
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
            self.logger.info("packet out dpid:'%s' in_port:'%s'", datapath.id, in_port)
            datapath.send_msg(out)

        if dhcp_r and DHCP_SERVER_DISCOVERED:
            print"blah"
            #do dhcp request stuff

        if dhcp_a and DHCP_SERVER_DISCOVERED:
            print"blah2"
            #do dhcp reply stuff

