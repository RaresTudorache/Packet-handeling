from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4State14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4State14, self).__init__(*args, **kwargs)
        self.ht = set()

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
    
        #forward all packets between port 1 and 2
        dst, src = (eth.dst, eth.src)
        if in_port == 1:
            out_port = 2
        else:
            out_port = 1
        acts = [psr.OFPActionOutput(out_port)]
        tcpheader_dict = {}
        #if TCP packet -> extract the flow key in a tuple
        if pkt.get_protocols(tcp.tcp):
            eth_tcp = pkt.get_protocols(tcp.tcp)[0]
            eth_ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
            tcpheader_dict[pkt] = (eth.src, eth.dst, eth_tcp.src_port, eth_tcp.dst_port)
            #if packet comes from port 1
            if in_port == 1:
                if tcpheader_dict[pkt] not in self.ht:
                    self.ht.add(tcpheader_dict[pkt])
                    #also insert the flow in the switch
                    mtc = psr.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, ipv4_src=eth_ipv4.src, ipv4_dst=eth_ipv4.dst, tcp_src=eth_tcp.src_port, tcp_dst=eth_tcp.dst_port)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return

            #if packet comes from port 2
            elif in_port == 2:
                if (eth.dst, eth.src, eth_tcp.dst_port, eth_tcp.src_port) in self.ht:
                    mtc = psr.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src, ipv4_src=eth_ipv4.src, ipv4_dst=eth_ipv4.dst, tcp_src=eth_tcp.src_port, tcp_dst=eth_tcp.dst_port)
                    self.add_flow(dp, 1, mtc, acts, msg.buffer_id)
                    if msg.buffer_id != ofp.OFP_NO_BUFFER:
                        return
                #drop it otherwise
                else:
                    acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
# sudo mn --topo single,2 --mac --controller remote --switch ovsk
