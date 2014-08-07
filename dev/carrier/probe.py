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

from cassandra.cluster import Cluster

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

class Probe(app_manager.RyuApp):
    
    global db_session
    
    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Probe) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        #create connection to customer database
        cluster = Cluster()
        db_session = cluster.connect('customers')
        
    ## function -> is this a valid "customer"?
    # unique token valid? yay? go ahead, nay? drop packet
    
    ## function -> what is this service
    # how do we handle this? do we faciliate a DHCP connection here? 
    # or are they a ppp/vlan/mpls etc customer
    
    #### getter/setter functions, split out by tables
    #### some will need to be private only
    #### primary want to be reading from database
    #### will want to be writing to the session table though to update
    
    ### HANDLE TABLE
    
    ### CUSTOMER INFO TABLE
    
    ### NETWORK INFO TABLE
    
    ### SERVICE INFO TABLE
    
    ### AUTHENTICATOR TABLE
    
    ### AUTHENTICATOR INFO TABLE
    
    ### SESSION TABLE
    
    ### BILLING TABLE
    
    

