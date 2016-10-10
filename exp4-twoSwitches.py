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

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet, ipv4
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

#custom libraries
import presentation

#python libraries
import re

class Exp4(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Exp4, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_of_experiment = ['00:00:00:00:01:02', 
                                  '00:00:00:00:11:04', 
                                  '00:00:00:00:21:04',
                                  '00:00:00:00:01:03', 
                                  '00:00:00:00:21:03',
                                  '00:00:00:00:01:06', 
                                  '00:00:00:00:21:06', 
                                  '00:00:00:00:01:10', 
                                  '00:00:00:00:31:06']
        
        # A class for showing things in useful format
        self._press = presentation.Presentation()
        self._press.boot()
        
        self._exp4 = True #Are we doing exp4?
        self.default_path = False
        
        self.ovsk_mac = self.mac_of_experiment[0]
        self.ovsk_ip = '10.1.14.102'
        
        self.ovsk_server_mac = self.mac_of_experiment[5]
        self.ovsk_server_ip = '12.1.14.106'
        
        self.default_path_mac = self.mac_of_experiment[1]
        self.default_path_ip = '10.1.14.104'
        
        self.alternate_path_mac = self.mac_of_experiment[3]
        self.alternate_path_ip = '10.1.14.103'
        
        self.source_mac = self.mac_of_experiment[7]
        self.source_ip = '10.1.14.110'
        
        self.reverse_default_mac = self.mac_of_experiment[2]
        self.reverse_default_ip = '12.1.14.104'
        
        self.reverse_alternate_mac = self.mac_of_experiment[4]
        self.reverse_alternate_ip = '12.1.14.103'
        
        self.server_mac = self.mac_of_experiment[6]
        self.server_ip = '10.30.30.1'
        
        self.default_path_port = 1
        self.alternate_path_port = 2
        self.source_port = 3
        
        self.default_arp_table = {}

        self.switches_dpid_to_mac = {}
        
        # Converting the MAC addresses to decimal to compare with the passed dpid
        self.ovsk_dpid = int(re.sub('[:]', '', self.ovsk_mac), 16)
        self.ovsk_server_dpid = int(re.sub('[:]', '', self.ovsk_server_mac), 16)
        self.switches_dpid_to_mac = {self.ovsk_dpid : self.ovsk_mac,
                                     self.ovsk_server_dpid : self.ovsk_server_mac}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """First message from switch"""
        
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        print "--->[%s] Switch features" % datapath.id

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)        
        self.mac_to_port.setdefault(datapath.id, {})
        self.default_arp_table.setdefault(datapath.id, {})
        
        self._fix_arp_to_server(datapath.id)
        
    def _fix_arp_to_server(self, dpid):
        """Changes the arp table of the server IP entry according to the test"""
        
        if dpid not in self.switches_dpid_to_mac:
            # ignoring other switches
            return
        
        print "--->[%s] Filling ARP table" % dpid
        if dpid == self.ovsk_dpid:
            self.default_arp_table[dpid] = {self.server_ip : self.server_mac,
                                            self.source_ip : self.source_mac,
                                            self.ovsk_ip : self.ovsk_mac,
                                            self.default_path_ip : self.default_path_mac,  
                                            self.alternate_path_ip : self.alternate_path_mac}
        elif dpid == self.ovsk_server_dpid:
            self.default_arp_table[dpid] = {self.server_ip : self.server_mac,
                                            self.source_ip : self.source_mac,
                                            self.ovsk_server_ip : self.ovsk_server_mac,
                                            self.reverse_default_ip : self.reverse_default_mac,                  self.reverse_alternate_ip : self.reverse_alternate_mac}
        

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, _timeout=0):
        """Adding a flow. Trying to keep it as general as possible"""
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if 'in_port' in match:
            _in_port = match['in_port']
            _ip_dst = match['ipv4_dst']
            self._press.flowAdded(datapath, _in_port, _ip_dst)
        else:
            print(match)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, 
                                idle_timeout=_timeout,
                                priority=priority,
                                match=match, 
                                instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):        
        """Handling the arrival of a packet to the controller"""
        
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ip4_pkt = pkt.get_protocol(ipv4.ipv4)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        elif dpid not in self.switches_dpid_to_mac:
            # ignore other switches
            return
        
        dst = eth.dst
        src = eth.src
        
        if dst not in self.mac_of_experiment:
            print ("--->[%s] MAC destination unknown: %s, src: %s" % (dpid, dst, src))
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                pkt_arp = pkt.get_protocol(arp.arp)
                self._handle_arp(datapath, in_port, eth, pkt_arp)
            return
        else:
            self._press.showPkt(dpid, src, dst, in_port)

        # Matching the ipv4_dst of the packet and acting accordingly
        if not ip4_pkt:
            print ("--->[%s] Packet without destination IP protocol. Ignoring." % dpid)
            return
        elif (ip4_pkt.dst == self.server_ip) or (ip4_pkt.src == self.server_ip):
            self.handle_path(in_port, ip4_pkt, datapath, msg)
        else:
            print "--->[%s] Packet goes elsewhere: %s" % (dpid, ip4_pkt.dst)
            return
        
    def _handle_arp(self, dp, in_port, eth_pkt, pkt_arp):
        """Handling ARP request and providing a reply based on our table"""
        
        if pkt_arp.opcode != arp.ARP_REQUEST:
            # ignore all except arp requests
            return
        elif pkt_arp.dst_ip not in self.default_arp_table[dp.id]:
            print "[%s] ARP not in default table, dst: %s" % (dp.id, pkt_arp.dst_ip)
            return
        
        req_dst = pkt_arp.dst_ip
        print ("--->[%s] Handling ARP message from %s, asking for: %s" % (dp.id, eth_pkt.src, req_dst))
        
        # Creating an arp reply message
        # Starting with a common ethernet frame from ovsk to requester
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(ethertype=eth_pkt.ethertype,
                                          dst=eth_pkt.src,
                                          src=self.switches_dpid_to_mac[dp.id]))
        
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                src_mac=self.default_arp_table[dp.id][req_dst],
                                src_ip=req_dst,
                                dst_mac=pkt_arp.src_mac,
                                dst_ip=pkt_arp.src_ip))
        
        self._send_packet(dp, in_port, pkt)
        
    def _send_packet(self, dp, port, pkt):
        """Sending a packet, generally comming from _handle_arp"""
        
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        print ("Sending ARP reply: %s" % (pkt,))
        
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=dp,
                                 buffer_id=ofproto.OFP_NO_BUFFER,
                                 in_port=ofproto.OFPP_CONTROLLER,
                                 actions=actions,
                                 data=data)
        dp.send_msg(out)
    
    def handle_path(self, in_port, ip4_pkt, datapath, msg):
        """Halding the flow mods for the default path"""
        
        dpid = datapath.id
        parser = datapath.ofproto_parser
        out_port = None
        dst_to = None
            
        # matching from source to server and back
        if dpid == self.ovsk_dpid:
            dst_to = self.default_path_mac
            out_port = self.default_path_port
            if self.default_path == False:
                dst_to = self.alternate_path_mac
                out_port = self.alternate_path_port
                                        
            self.mac_to_port[dpid][dst_to] = out_port
            
            #actions to reach Server
            actions_to = [parser.OFPActionOutput(self.mac_to_port[dpid][dst_to])]  
            
            #matching packets to Server
            match_to = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, in_port=self.source_port, ipv4_dst=ip4_pkt.dst)
            
            # now doing the reverse path
            dst_local = self.source_mac
            
            #writing the port towards Source
            self.mac_to_port[dpid][dst_local] = self.source_port
            
            #actions to reach Source
            actions_local = [parser.OFPActionOutput(self.mac_to_port[dpid][dst_local])]
        
            #matching packets to Source
            match_local = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip4_pkt.src)
        
            # flow_mod & packet_out
            self.add_flow(datapath, 1, match_to, actions_to)
            self.add_flow(datapath, 1, match_local, actions_local)
            
        
            data = None
            if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port, 
                                      actions=actions_to, 
                                      data=data)
            datapath.send_msg(out)
        elif dpid == self.ovsk_server_dpid:
            return
            
            