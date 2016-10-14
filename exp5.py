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
from ryu.lib.packet import ethernet, ipv4, udp, tcp
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.lib.packet import arp

#custom libraries
import presentation

#python libraries
import re
class Exp5(app_manager.RyuApp):
    """Performing path redirection based on UDP/TCP destination port"""

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Exp5, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.mac_of_experiment = ['00:00:00:00:01:02', 
                                  '00:00:00:00:11:04', 
                                  '00:00:00:00:21:04',
                                  '00:00:00:00:01:03', 
                                  '00:00:00:00:21:03',
                                  '00:00:00:00:01:06', 
                                  '00:00:00:00:21:06', 
                                  '00:00:00:00:01:10', 
                                  '00:00:00:00:31:06',
                                  '00:00:00:00:21:10']
        
        # A class for showing things in useful format
        self._press = presentation.Presentation()
        self._press.boot()
        
        self.default_path = False
        
        self.server_tcp_ports = [9999, 9998]
        
        self.ovsk_mac = self.mac_of_experiment[0]
        self.ovsk_ip = '10.1.14.102'
        
        self.ovsk_server_mac = self.mac_of_experiment[5]
        self.ovsk_server_ip = '12.1.14.106'
        
        self.default_path_mac = self.mac_of_experiment[7]
        self.default_path_ip = '10.1.14.110'
        
        self.alternate_path_mac = self.mac_of_experiment[3]
        self.alternate_path_ip = '10.1.14.103'
        
        self.reverse_default_mac = self.mac_of_experiment[2]
        self.reverse_default_ip = '12.1.14.104'
        
        self.reverse_alternate_mac = self.mac_of_experiment[4]
        self.reverse_alternate_ip = '12.1.14.103'
        
        self.server_mac = self.mac_of_experiment[8]
        self.server_ip = '10.30.30.1'
        
        self.default_path_port = 1
        self.alternate_path_port = 2
        
        self.default_arp_table = {}

        self.switches_dpid_to_mac = {}
        
        self.flows = {}
        
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
        self.flows.setdefault(datapath.id, {})
        
        self._fix_arp_to_server(datapath)
        
    def _fix_arp_to_server(self, dp):
        """Changes the arp table of the server IP entry according to the test"""
        
        dpid = dp.id
        if dpid not in self.switches_dpid_to_mac:
            # ignoring other switches
            return
        
        print "--->[%s] Filling ARP table" % dpid
        if dpid == self.ovsk_dpid:
            self.default_arp_table[dpid] = {self.ovsk_ip : self.ovsk_mac,
                                            self.default_path_ip : self.default_path_mac,  
                                            self.alternate_path_ip : self.alternate_path_mac}
        elif dpid == self.ovsk_server_dpid:
            self.default_arp_table[dpid] = {self.ovsk_server_ip : self.ovsk_server_mac,
                                            self.reverse_default_ip : self.reverse_default_mac,                  self.reverse_alternate_ip : self.reverse_alternate_mac}
        
        print "\tARP table for [%s]: %s" % (dpid, self.default_arp_table[dpid],)
        
    def _handle_arp(self, dp, in_port, eth_pkt, pkt_arp):
        """Handling ARP request and providing a reply based on our table"""
        
        if pkt_arp.opcode != arp.ARP_REQUEST:
            # ignore all except arp requests
            return
        elif pkt_arp.dst_ip not in self.default_arp_table[dp.id]:
            print "--->[%s] ARP not in default table, dst: %s" % (dp.id, pkt_arp.dst_ip)
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
        
        # updating local tables
        self.default_arp_table[dp.id][pkt_arp.src_ip] = pkt_arp.src_mac
        self.mac_to_port[dp.id][pkt_arp.src_mac] = in_port        
        
        self._send_arp_reply(dp, pkt, in_port)

    def _send_arp_reply(self, dp, pkt, port):
        """Sending a packet comming from _handle_arp"""
        
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        pkt.serialize()
        print ("--->[%s] Sending ARP reply: %s" % (dp.id, pkt,))
        
        data = pkt.data
        
        actions = [parser.OFPActionOutput(port=ofproto.OFPP_IN_PORT)]
        
        out = parser.OFPPacketOut(datapath=dp,
                                 buffer_id=ofproto.OFP_NO_BUFFER,
                                 in_port=port,
                                 actions=actions,
                                 data=data)
        dp.send_msg(out)
        
        print "--->[%s] Sending through port: %s\n" % (dp.id, port)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0, buffer_id=None):
        """Adding a flow. Trying to keep it as general as possible"""
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        _in_port = None
        _ip_dst = None
        
        print "--->[%s] Adding flow" % datapath.id
        
        if 'in_port' in match:
            _in_port = match['in_port']
            _ip_dst = match['ipv4_dst']
        else:
            print(match)

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, 
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath,
                                priority=priority,
                                match=match, 
                                instructions=inst)
        datapath.send_msg(mod)
        self._press.flowAdded(datapath, _in_port, _ip_dst)

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
        tcp_seg = pkt.get_protocol(tcp.tcp)
        udp_seg = pkt.get_protocol(udp.udp)
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        elif dpid not in self.switches_dpid_to_mac:
            # ignore other switches
            return
        
        dst = eth.dst
        src = eth.src
        
        # Catching ARP requests
        if dst not in self.mac_of_experiment:
            if eth.ethertype == ether_types.ETH_TYPE_ARP:
                pkt_arp = pkt.get_protocol(arp.arp)
                if pkt_arp:
                    print "--->[%s] Going to handle ARP request, in_port: %s" % (dpid, in_port)
                    self._handle_arp(datapath, in_port, eth, pkt_arp)
                else:
                    print "--->[%s] Void ARP request from: %s" % (dpid, src)
            else:
                #ignoring frames directed to devices outside the experiment
                return
        else:
            self._press.showPkt(dpid, src, dst, in_port)

        # Dismissing packets without IP information (only ARP above are admitted)
        if not ip4_pkt:
            print ("--->[%s] Packet without destination IP protocol. Ignoring.\n" % dpid)
            return
        
        # unleashing behaviour based on protocol
        if dpid == self.ovsk_dpid:
            if icmp_pkt:
                self.handle_icmp(in_port, eth, icmp_pkt, ip4_pkt, datapath, msg)
            elif tcp_seg:
                if udp_seg:
                    print "[%s]---> Also with UDP, src: %s, dst: %s" % (dpid, udp_seg.src_port, udp_seg.dst_port)
                self.handle_tcp(in_port, eth, ip4_pkt, tcp_seg, datapath, msg)
            else:
                print "--->[%s] No known protocol to process" % (dpid)
        elif dpid == self.ovsk_server_dpid:
            self.bouncer(in_port, eth, icmp_pkt, ip4_pkt, tcp_seg, datapath, msg)
        else:
            return
        
    def handle_icmp(self, in_port, eth, icmp_pkt, ip4_pkt, datapath, msg):
        """Handling ICMP packets"""
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dst_to = None
        out_port = None
        
        print "--->[%s] ICMP packet, type: %s, code: %s, ip_src: %s, ip_dst: %s" % (dpid, icmp_pkt.type, icmp_pkt.code, ip4_pkt.src, ip4_pkt.dst)
        
        if self.default_path == True:
            dst_to = self.default_path_mac
            out_port = self.default_path_port
        else:
            dst_to = self.alternate_path_mac
            out_port = self.alternate_path_port
            
        print "--->[%s] Sending through port: %s, mac: %s" % (dpid, out_port, dst_to)
        
        self.mac_to_port[dpid][dst_to] = out_port
        
        #actions to reach destination
        actions = [parser.OFPActionSetField(eth_dst=dst_to),
                   parser.OFPActionOutput(port=out_port)]  

        #matching packets to destination
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, 
                                ipv4_dst=ip4_pkt.dst,
                                icmpv4_type=8)
        
        ################################################################################
        # now doing the reverse path
        dst_back = eth.src

        #writing the port towards the source
        out_port_back = ofproto.OFPP_LOCAL
        self.mac_to_port[dpid][dst_back] = out_port_back

        #actions to reach the source
        actions_back = [parser.OFPActionOutput(port=out_port_back)]

        #matching packets to the source
        match_back = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                     ipv4_dst=ip4_pkt.src,
                                     icmpv4_type=0)
       
        # flow_mod & packet_out
        self.add_flow(datapath, 10, match, actions)
        self.add_flow(datapath, 10, match_back, actions_back)

        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=ofproto.OFPP_IN_PORT, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)
        
    def handle_tcp(self, in_port, eth, ip4_pkt, tcp_seg, datapath, msg):
        """Handling TCP segments"""
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        out_port = None
        dst_to = None
        
        dst_tcp = None
        src_tcp = None
        
        if tcp_seg.dst_port in self.server_tcp_ports:
            """Checking the destination of the ports"""
            dst_tcp = tcp_seg.dst_port
            src_tcp = tcp_seg.src_port
            
            print "--->[%s] TCP destination: %s, origin: %s" % (dpid, dst_tcp, src_tcp)
            if dst_tcp == self.server_tcp_ports[0]:
                self.default_path = True
            else:
                self.default_path = False
        else:
            print "--->[%s] Alien TCP segment, dst_port: %s" % (dpid, tcp_seg.dst_port)
            return
                
        if self.default_path == True:
            dst_to = self.default_path_mac
            out_port = self.default_path_port
        else:
            dst_to = self.alternate_path_mac
            out_port = self.alternate_path_port
        
        self.mac_to_port[dpid][dst_to] = out_port

        #actions to reach Server
        actions = [parser.OFPActionSetField(eth_dst=dst_to), 
                   parser.OFPActionOutput(port=out_port)]  

        #matching packets to Server
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=6,
                                tcp_dst=dst_tcp,
                                ipv4_dst=ip4_pkt.dst)
        
        ################################################################################
        # now doing the reverse path
        dst_local = eth.src

        #writing the port towards the source
        self.mac_to_port[dpid][dst_local] = in_port

        #actions to reach the source
        actions_back = [parser.OFPActionOutput(port=in_port)]

        #matching packets towards source
        match_back = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6,
                                    tcp_dst=src_tcp,
                                    ipv4_dst=ip4_pkt.src)

        # flow_mod & packet_out
        self.add_flow(datapath, 10, match, actions)
        self.add_flow(datapath, 10, match_back, actions_back)

        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=ofproto.OFPP_IN_PORT, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)
       
    def bouncer(self, in_port, eth, icmp_pkt, ip4_pkt, tcp_seg, datapath, msg):
        """Bounce back packets"""
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out_port = None
        dst_to = None
    
        #saving mac and port to our table
        self.mac_to_port[dpid][eth.src] = in_port
        dst_to = eth.dst    
        
        if dst_to == self.ovsk_server_mac:
            out_port = ofproto.OFPP_LOCAL
            self.mac_to_port[dpid][dst_to] = out_port
        elif dst_to not in self.mac_to_port[dpid]:
            return
        
        if icmp_pkt:
            self.bounce_icmp(in_port, eth, icmp_pkt, ip4_pkt, datapath, msg)
        elif tcp_seg:
            self.bounce_tcp(in_port, eth, ip4_pkt, tcp_seg, datapath, msg)
            
            
    def bounce_icmp(self, in_port, eth, icmp_pkt, ip4_pkt, datapath, msg):
        """Bouncer of ICMP requests"""
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        out_port = None
        dst_to = None
        
        print "--->[%s] ICMP packet, type: %s, code: %s, ip_src: %s, ip_dst: %s" % (dpid, icmp_pkt.type, icmp_pkt.code, ip4_pkt.src, ip4_pkt.dst)
        
        dst_to = eth.dst
        if dst_to == self.ovsk_server_mac:
            out_port = ofproto.OFPP_LOCAL
            self.mac_to_port[dpid][dst_to] = out_port
        elif dst_to not in self.mac_to_port[dpid]:
            print "--->[%s] Destination ofport unknown, eth_dst: %s" % dst_to
            return
            
        #actions to reach Server
        actions = [parser.OFPActionOutput(port=self.mac_to_port[dpid][dst_to])]  

        #matching packets to Server
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                ipv4_dst=ip4_pkt.dst,
                                icmpv4_type=8)

        ###############################################################################
        # now doing the reverse path, trying to match all relevant destinations
        dst_back = eth.src

        #actions to reach the source
        actions_back = [parser.OFPActionSetField(eth_dst=dst_back),
                         parser.OFPActionOutput(port=in_port)]

        #matching packets to the source
        match_back = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                     ipv4_dst=ip4_pkt.src,                                   
                                     icmpv4_type=0)

        # flow_mod & packet_out
        self.add_flow(datapath, 10, match, actions)
        self.add_flow(datapath, 10, match_local, actions_local)

        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=ofproto.OFPP_IN_PORT, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)   
        
    def bounce_tcp(self, in_port, eth, ip4_pkt, tcp_seg, datapath, msg):
        """Bouncer of TCP segments"""
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        dst_tcp = None
        src_tcp = None
        
        dst_to = eth.dst
        
        if tcp_seg.dst_port in self.server_tcp_ports:
            """Checking the destination of the ports"""
            dst_tcp = tcp_seg.dst_port
            src_tcp = tcp_seg.src_port
            
            actions = [parser.OFPActionOutput(port=self.mac_to_port[dpid][dst_to])]  
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=6,
                                    tcp_dst=dst_tcp,
                                    ipv4_dst=ip4_pkt.dst)
        else:
            print "--->[%s] Dropping bounce due to alien TCP dest: %s" % (dpid, dst_tcp)
            return
        ##########################################################################################
        dst_back = eth.src

        actions_back = [parser.OFPActionSetField(eth_dst=dst_back),
                        parser.OFPActionOutput(port=self.mac_to_port[dpid][dst_back])]
        
        match_back = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                     ip_proto=6,
                                     tcp_dst=src_tcp,
                                     ipv4_dst=ip4_pkt.src)
        
        self.add_flow(datapath, 10, match, actions)
        self.add_flow(datapath, 10, match_back, actions_back)
    
        data = None
        if msg.buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=ofproto.OFPP_IN_PORT, 
                                  actions=actions, 
                                  data=data)
        datapath.send_msg(out)
        