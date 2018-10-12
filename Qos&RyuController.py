
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types

from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp




class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


FORWARD_TABLE = 10
APP_TABLE = 15
FILTER_TABLE = 5

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.add_default_table(datapath)
        self.add_filter_table(datapath)
        
        self.apply_filter_table_rules(datapath)
        self.apply_filter_table_rules2(datapath)
            
     #   self.apply_filter_table_rules(datapath)
        self.app_table(datapath)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        print("------------")
        print(buffer_id)
        print("------------")
        print(priority)

        if priority == 2:
        

            if buffer_id:

                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=65535, table_id=APP_TABLE,
                                        match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=65535   ,
                                            match=match, table_id=APP_TABLE,
                                            instructions=inst)

        

        if priority != 2:
            if buffer_id:

                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                            priority=priority, table_id=FORWARD_TABLE,
                                            match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                            match=match, table_id=FORWARD_TABLE,
                                            instructions=inst)

        datapath.send_msg(mod)




    def add_default_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FILTER_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=0, instructions=inst)
        datapath.send_msg(mod)

    def add_filter_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(FORWARD_TABLE)]
        mod = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
                                priority=0, instructions=inst)
        datapath.send_msg(mod)


    def apply_filter_table_rules(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(APP_TABLE)]


        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_dst="10.1.1.3",ip_proto=in_proto.IPPROTO_TCP)


        mod = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
                                priority=10000, match=match, instructions=inst)
        datapath.send_msg(mod)

    def apply_filter_table_rules2(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionGotoTable(APP_TABLE)]


        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,ipv4_src="10.1.1.3",ip_proto=in_proto.IPPROTO_TCP)


        mod = parser.OFPFlowMod(datapath=datapath, table_id=FILTER_TABLE,
                                priority=10000, match=match, instructions=inst)
        datapath.send_msg(mod)
    def app_table(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]


        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                            actions)]

    
        mod = parser.OFPFlowMod(datapath=datapath, table_id=APP_TABLE,
                                priority=0, match=match, instructions=inst)
        datapath.send_msg(mod)



    #def add_APP_TABLE(self, datapath):
     #   ofproto = datapath.ofproto
     #   parser = datapath.ofproto_parser
      #  actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                     #   ofproto.OFPCML_NO_BUFFER)]
     #   inst =[parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                  #           actions)]



      #  mod = parser.OFPFlowMod(datapath=datapath, table_id=APP_TABLE,instructions=inst)

      #  datapath.send_msg(mod)





    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        flag = 0

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:

            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip = pkt.get_protocol(ipv4.ipv4)
                srcip = ip.src
                dstip = ip.dst
                print (dstip)
                protocol = ip.proto
               
                if protocol == in_proto.IPPROTO_ICMP:
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol)


                elif protocol == in_proto.IPPROTO_TCP:
                    t = pkt.get_protocol(tcp.tcp)
    
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, tcp_src=t.src_port, tcp_dst=t.dst_port,)
                    if dstip == "10.1.1.3":
                        flag = 2
                    if srcip == "10.1.1.3":
                        flag = 2    
                elif protocol == in_proto.IPPROTO_UDP:
                    u = pkt.get_protocol(udp.udp)
                    match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=srcip, ipv4_dst=dstip, ip_proto=protocol, udp_src=u.src_port, udp_dst=u.dst_port,)


                    
            	
            	# flow_mod & packet_out
               # if msg.buffer_id != ofproto.OFP_NO_BUFFER and flag == 2:
                #    self.add_flow(datapath, 5, match, actions, msg.buffer_id)
                 #   return



                if flag == 2:
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath,2, match, actions, msg.buffer_id)
                        return  
                        
                    else:
                        self.add_flow(datapath,2, match, actions)

                if flag != 2:

                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:    
                        self.add_flow(datapath, 10000, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 10000, match, actions)

        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
