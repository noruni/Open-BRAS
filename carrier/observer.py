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

import ConfigParser, yaml

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether, inet
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib import addrconv

class Observer(app_manager.RyuApp):

	def __init__(self, *args, **kwargs):
        super(Observer, self).__init__(*args, **kwargs)
        #Let's start implementing some configuration file support
        config = ConfigParser.RawConfigParser()
        configFileName = '/root/binaries/ryu/ryu/app/carrier/carrier.cfg'
        self.logger.info("[ADMIN] (Observer) Loading configuration file [%s]" % (configFileName))
        config.read(configFileName)
        
        self.portdb = None
        self.vlandb = {}
        
        with open('vlans.yml', 'r') as stream:
            self.portdb = yaml.load(stream)
            
        for port in self.portdb:
            vlans = self.portdb[port]['vlans']
            ptype = self.portdb[port]['type']
            if type(vlans) is list:
                for vlan in vlans:
                   if vlan not in self.vlandb:
                       self.vlandb[vlan] = {'tagged': [], 'untagged': []}
                   self.vlandb[vlan][ptype].append(port)
            else:
                if vlans not in self.vlandb:
                    self.vlandb[vlans] = {'tagged': [], 'untagged': []}
                self.vlandb[vlans][ptype].append(port)
            
        