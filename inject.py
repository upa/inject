#
#    inject function controller
#

import logging
import ConfigParser


from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.controller import dpset
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet


"""
+ inject overview
    packets with inject-port (L4 port number) are taken through
    an injected function. packets from port-a are injected to port-a
    of specified function, and packets from port-b are injected
    to port-b. packets from functions are also injected to corresponding
    port-X of openflow switch.
"""

logging.basicConfig (level = logging.DEBUG,
                     format = "%(asctime)s:inject:%(funcName)s")


PRIO_DEFAULT_FLOW = 0x0001
PRIO_PASS_FLOW    = 0x0010
PRIO_INJECT_FLOW  = 0x0100


class OFSwitch () :

    def __init__ (self, dpid, porta, portb) :
        
        self.dpid = dpid
        self.porta = porta
        self.portb = portb
        self.ports = []  # OpenFlow Port Numbers
        self.ifuncs = [] # InjectFunction class
        self.present = False
        return


    def attach_function (self, ifunc) :

        if ifunc in self.ifuncs :
            logging.error ("function %s is already attached." % ifunc.name)
            return False

        ifunc.attached = True
        self.ifuncs.append (ifunc)

        # XXX: add new flow entry here ?

        return True


    def detach_function (self, ifunc) :
        
        if not ifunc in self.ifuncs :
            logging.error ("function %s is not attached." % ifunc.name)
            return False

        ifunc.attached = False
        self.ifuncs.remove (ifunc)

        # XXX: delete new flow entry here ?

        return

    def add_port (self, port) :
        if port in self.ports : 
            logging.error ("duplicated port %d." % port)
            return

        self.ports.append (port)
        return


    def del_port (self, port) :
        if not port in self.ports :
            logging.errpr ("port %d does not exist." % port)
            return

        self.ports.remove (port)
        return

    
class InjectFunction () :

    """ Injected function class  """

    def __init__ (self, name, porta, portb, iport) :
        self.name = name
        self.porta = porta
        self.portb = portb
        self.iport = iport
        self.attached = False
        return



class Inject (app_manager.RyuApp) :
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = { 'dpset' : dpset.DPSet, }

    def __init__ (self, *args, **kwargs) :
        super (Inject, self).__init__ (*args, **kwargs)

        self.ofs = None
        self.ifuncs = []

        logging.info ("OpenFlow Controler \"inject\" start.")

        # load inject.ini
        candidates = ["inject.ini", "/etc/inject.ini",
                      "/usr/local/etc/inject.ini"]

        cf = ConfigParser.SafeConfigParser ()
        cf.read (candidates)

        # load OFSwitch settings
        logging.info ("load settings.")
        if not "settings" in cf.sections () :
            logging.error ("section \"settings\" is not found.")
            return
        
        dpid = cf.getint ("settings", "dpid")
        porta = cf.getint ("settings", "port-a")
        portb = cf.getint ("settings", "port-b")
        
        self.ofs = OFSwitch (dpid, porta, portb)

        # load other sections, they are functions
        
        for section in cf.sections () :
            if section == "settings" : continue

            logging.info ("load function setting \"%s\"" % section)

            name = section
            porta = cf.getint (section, "port-a")
            portb = cf.getint (section, "port-b")
            iport = cf.getint (section, "inject-port")
            attached = cf.getboolean (section, "default-attached")

            ifunc = InjectFunction (section, porta, portb, iport)
            self.ifuncs.append (ifunc)
            
            if attached :
                self.ofs.attach_function (ifunc)
            
        logging.info ("load config file is done. waiting switch join.")

        return


    def install_default_flows (self, datapath) :
        
        # install port-a <-> port-b flows on OFS.
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch (in_port = self.ofs.porta)
        act = [parser.OFPActionOutput (self.ofs.portb)]
        prio = PRIO_DEFAULT_FLOW
        self.send_flowmod (datapath, prio, match, act)

        match = parser.OFPMatch (in_port = self.ofs.portb)
        act = [parser.OFPActionOutput (self.ofs.porta)]
        prio = PRIO_DEFAULT_FLOW
        self.send_flowmod (datapath, prio, match, act)
        
        return

    def install_inject_flows (self, datapath, ifunc) :
        
        # install attached inject flows. match is L4 port number.
        # port-a.ofs -> port-a.ifunc, port-b.ofs -> port-b.ifunc
        # port-a.ifunc -> port-a.ofs, port-b.ifunc -> port-b.ofs

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install ofs -> ifunc flows
        def gen_match (in_port, ip_proto, ifunc_port, portdirect) :
            
            if ip_proto == inet.IPPROTO_TCP :
                if portdirect == "src" :
                    m = parser.OFPMatch (in_port = in_port,
                                         eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         tcp_src = ifunc_port)
                elif portdirect == "dst" :
                    m = parser.OFPMatch (in_port = in_port,
                                         eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         tcp_dst = ifunc_port)
            elif ip_proto == inet.IPPROTO_UDP :
                if portdirect == "src" :
                    m = parser.OFPMatch (in_port = in_port,
                                         eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         udp_src = ifunc_port)
                elif portdirect == "dst" :
                    m = parser.OFPMatch (in_port = in_port,
                                         eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         udp_dst = ifunc_port)
            return m

        tcp = inet.IPPROTO_TCP
        udp = inet.IPPROTO_UDP
        # install ofs -> ifunc flows
        match_tcp_src = gen_match (self.ofs.porta, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (self.ofs.porta, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (self.ofs.porta, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (self.ofs.porta, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (ifunc.porta)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)

        match_tcp_src = gen_match (self.ofs.portb, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (self.ofs.portb, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (self.ofs.portb, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (self.ofs.portb, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (ifunc.portb)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)

        # install ifunc -> ofs flows
        match_tcp_src = gen_match (ifunc.porta, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (ifunc.porta, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (ifunc.porta, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (ifunc.porta, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (self.ofs.porta)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)

        match_tcp_src = gen_match (ifunc.portb, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (ifunc.portb, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (ifunc.portb, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (ifunc.portb, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (self.ofs.portb)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)

        return


    def install_flows (self, ev) :
        datapath = ev.msg.datapath

        logging.info ("install default port-a.ofs <-> port-b.ofs flows.")
        self.install_default_flows (datapath)

        for ifunc in self.ifuncs :
            if ifunc.attached :
                logging.info ("install function \"%s\" flows." % ifunc.name)
                self.install_inject_flows (datapath, ifunc)
        return


    def remove_flows (self, ev) :
        logging.info ("remove all flows.")

        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install DEL with * match
        match = parser.OFPMatch ()
        ins = []
        mod = parser.OFPFlowMod (datapath = datapath, match = match,
                                 instructions = ins,
                                 command = ofproto.OFPFC_DELETE)
        datapath.send_msg (mod)
        return


    def send_flowmod (self, datapath, priority, match, act,
                      idle = 0, hard = 0) :

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        ins = [parser.OFPInstructionActions (ofproto.OFPIT_APPLY_ACTIONS, act)]
        mod = parser.OFPFlowMod (datapath = datapath, priority = priority,
                                 match = match, instructions = ins,
                                 idle_timeout = idle, hard_timeout = hard)

        datapath.send_msg (mod)
        return

    

    @set_ev_cls (ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler (self, ev) :

        dpid = ev.msg.datapath.id

        if self.ofs.dpid != dpid :
            return

        logging.info ("Switch [%d] is connected." % dpid)
        self.ofs.present = True

        # XXX: remove all enries, and install flow entries.
        self.remove_flows (ev)
        self.install_flows (ev)
        return

    
    @set_ev_cls (dpset.EventDP)
    def dp_handler (self, ev) :
        if not ev.enter :
            # leave openflow switch
            if self.ofs.dpid == ev.dp.id :
                logging.error ("openflow siwtch [%d] left" % ev.dp.id)
                self.ofs.present = False
            return

        if self.ofs.dpid == ev.dp.id :
            self.ofs.present = True
        else :
            return

        for port in ev.dp.ports :
            self.ofs.add_port (port)

