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
    
    ## don't worry about exposing this database info
    ## it's just a proof-of-concept and will store nothing of value
        
    ## function -> is this a valid "customer"?
    # unique token valid? yay? go ahead, nay? drop packet
    
    ## function -> what is this service
    # how do we handle this? do we faciliate a DHCP connection here? 
    # or are they a ppp/vlan/mpls etc customer

    
    #### getter/setter functions, split out by tables
    #### some will need to be private only
    #### primary want to be reading from database
    #### will want to be writing to the session table though to update

##########################    
    ### HANDLE TABLE
    
    ## get id
    ## get info_id
    ## get network_id
    ## get billing_id
    
##########################
    ### CUSTOMER INFO TABLE

    ## get fname
    ## get lname
    ## get phys_addr
    ## get postal_addr
    ## get email
    ## get phone

##########################    
    ### NETWORK INFO TABLE

    ## get service_id
    ## get auth_item_id
    ## get session_id
    ## get cvid
    ## get svid
    ## get order_num
    ## get static_IP
    ## get lan_type

##########################    
    ### SERVICE INFO TABLE

    ## get serv_description
    ## get handover
    ## get variant

##########################    
    ### AUTHENTICATOR TABLE

    ## get auth_id
    ## get token
    ## get device
    ## get auth_type

##########################    
    ### AUTHENTICATOR INFO TABLE

    ## get auth_item_id
    ## get tokens[auth_id,<..>]

##########################    
    ### SESSION TABLE
    
    ## get session_start
    ## get session_end
    ## get termination
    ## get nas_id
    ## get nas_IP
    ## get framed_IP
    ## get client_MAC
    ## get station_MAC

    ## set session_start    
    ## set session_end
    ## set termination    
    ## set nas_id    
    ## set nas_IP
    ## set framed_IP
    ## set client_MAC
    ## set station_MAC

##########################
    ##### we probably don't need to expose this table 
    ##### the thought being that eventually RADIUS
    ##### would take over accounting stuff
    
    ### BILLING TABLE
    ## get bill_type
    ## get acc_num
    ## get bill_description
    ## get expiry
    ## get debit_date

##########################
