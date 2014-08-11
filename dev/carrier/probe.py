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
import pycassa

from pycassa.pool import ConnectionPool
from pycassa.columnfamily import ColumnFamily
from ryu.base import app_manager

class Probe(app_manager.RyuApp):
    
    global db_session
    
    def connect(self):
        pool = pycassa.ConnectionPool(keyspace='customers',server_list=['127.0.0.1:9160'])
        col_fam = ColumnFamily(pool,'handle');
        readData = col_fam.get(1,columns=['billing_item_id', 'info_item_id'])
        for k, v in readData.items():
            print k, v
    
    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Probe) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        #create connection to customer database
        self.connect()
    
    
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
