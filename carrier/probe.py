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
from pycassa.index import create_index_expression
from pycassa.index import create_index_clause
from ryu.base import app_manager

class Probe(app_manager.RyuApp):
    
    global pool
    pool = None
    
    def connect(self):
        pool = pycassa.ConnectionPool(keyspace='customers',server_list=['127.0.0.1:9160'])

    
    def close(self):
        pool.dispose()
    
    def __init__(self, *args, **kwargs):
        super(Probe, self).__init__(*args, **kwargs)
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Probe) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
    
    
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
    ## indexed by each column so we can do reverse lookups
    def handle_get_id_viaInfo(self,pool,key):
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'handle')
        expr = create_index_expression('info_item_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
        
    def handle_get_id_viaBilling(self,pool,key):
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'handle')
        expr = create_index_expression('billing_item_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
    
    def handle_get_id_viaNetwork(self,pool,key):
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'handle')
        expr = create_index_expression('network_item_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
    
    ## get info_id
    def handle_get_infoid(self,pool,key):
        handle = ColumnFamily(pool,'handle');
        data = handle.get(key,columns=['info_item_id'])
        return data.items()[0][1]
    
    ## get network_id
    
    def handle_get_networkid(self,pool,key):
        handle = ColumnFamily(pool,'handle');
        data = handle.get(key,columns=['network_item_id'])
        return data.items()[0][1]
    
    ## get billing_id
    def handle_get_billingid(self,pool,key):
        handlehandle = ColumnFamily(pool,'handle');
        data = handle.get(key,columns=['billing_item_id'])
        return data.items()[0][1]
    
    
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
    
    def network_get_id_viaAuth(self,pool,key):   
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'network_info')
        expr = create_index_expression('auth_item_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
        
    def network_get_id_viaService(self,pool,key):   
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'network_info')
        expr = create_index_expression('service_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
        
    def network_get_id_viaSession(self,pool,key):   
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'network_info')
        expr = create_index_expression('session_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret

    ## get service_id
    def network_get_serviceid(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['service_id'])
        return data.items()[0][1]
    
    ## get auth_item_id
    def network_get_authid(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['auth_item_id'])
        return data.items()[0][1]    
    
    ## get session_id
    def network_get_sessionid(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['session_id'])
        return data.items()[0][1]
    
    ## get cvid
    def network_get_cvid(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['cvid'])
        return data.items()[0][1]
    
    ## get svid
    def network_get_svid(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['svid'])
        return data.items()[0][1]
    
    ## get order_num
    def network_get_ordernum(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['order_num'])
        return data.items()[0][1]
    
    ## get static_IP
    def network_get_staticip(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['static_ip'])
        return data.items()[0][1]
    
    ## get lan_type
    def network_get_lantype(self,pool,key):
        handlehandle = ColumnFamily(pool,'network_info');
        data = handle.get(key,columns=['lan_type'])
        return data.items()[0][1]

##########################    
    ### SERVICE INFO TABLE

    ## get serv_description
    ## get handover
    ## get variant

##########################    
    ### AUTHENTICATOR TABLE

    ## get token_id

    def authenticator_get_token_id(self,pool,key):
        
        # if provided a column value key, get this token id
        ret = None
        token = ColumnFamily(pool,'authenticator')
        expr = create_index_expression('atoken',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
    
    ## get token
    def authenticator_get_token(self,pool,key):
        # if provided a row key, get this token
        token = ColumnFamily(pool,'authenticator');
        data = token.get(key,columns=['atoken'])
        return data.items()[0][1]
            
    ## get device
    def authenticator_get_device(self,pool,key):
        # if provided a row key, get this token
        token = ColumnFamily(pool,'authenticator');
        data = token.get(key,columns=['device'])
        return data.items()[0][1]
    
    ## get auth_type
    def authenticator_get_device(self,pool,key):
        # if provided a row key, get this token
        token = ColumnFamily(pool,'authenticator');
        data = token.get(key,columns=['atoken'])
        return data.items()[0][1]

##########################    
    ### AUTHENTICATOR INFO TABLE

    ## get auth_item_id
    def authenticatorlist_get_id(self,pool,key):
        ret = None
        token = ColumnFamily(pool,'authenticators_info')
        expr = create_index_expression('token_id',key)
        clause = create_index_clause([expr])
        result = token.get_indexed_slices(clause)
        for keyx,columnx in result;
            ret = keyx
        return ret
    
    ## get token_id
    def authenticatorlist_get_token_id(self,pool,key):
        handle = ColumnFamily(pool,'authenticators_info');
        data = handle.get(key,columns=['token_id'])
        return data.items()[0][1]

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
