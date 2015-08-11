#
#    inject function controller
#

import json
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


from webob.response import Response
from ryu.app.wsgi import (
    WSGIApplication, ControllerBase,
)


"""
+ inject overview
    packets with inject-port (L4 port number) are taken through
    an injected function. packets from port-a are injected to port-a
    of specified function, and packets from port-b are injected
    to port-b. packets from functions are also injected to corresponding
    port-X of openflow switch.
"""

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
        self.datapath = False
        self.present = False
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
    _CONTEXTS = { 
        'dpset' : dpset.DPSet, 
        'wsgi' : WSGIApplication,
        }

    def __init__ (self, *args, **kwargs) :

        super (Inject, self).__init__ (*args, **kwargs)

        logging.basicConfig (level = logging.DEBUG,
                             format = "%(asctime)s:inject:%(funcName)s")

        self.wsgi = kwargs['wsgi']


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
            if attached : ifunc.attached = True
            
        logging.info ("load config file is done. waiting switch join.")


        # load Restful API
        mapper = self.wsgi.mapper
        self.wsgi.registory['RestApi'] = { 'inject' : self }

        mapper.connect ('attach_ifunc', "/attach/{ifunc_name}",
                        controller = RestApi,
                        action = 'attach_ifunc',
                        conditions = dict (method = ['PUT']))

        mapper.connect ('detach_ifunc', "/detach/{ifunc_name}",
                        controller = RestApi,
                        action = 'detach_ifunc',
                        conditions = dict (method = ['PUT']))

        mapper.connect ('install_all_flows', "/installall",
                        controller = RestApi,
                        action = 'install_all_flows',
                        conditions = dict (method = ['PUT']))
        
        mapper.connect ('remove_all_flows', "/removeall",
                        controller = RestApi,
                        action = 'remove_all_flows',
                        conditions = dict (method = ['PUT']))

        mapper.connect ('list_ifuncs', '/list',
                        controller = RestApi,
                        action = 'list_ifuncs',
                        conditions = dict (method = ['GET']))

        return


    def find_ifunc (self, ifunc_name) :
        for ifunc in self.ifuncs :
            if ifunc.name == ifunc_name :
                return ifunc
        return None


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
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_dst, act)

        match_tcp_src = gen_match (self.ofs.portb, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (self.ofs.portb, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (self.ofs.portb, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (self.ofs.portb, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (ifunc.portb)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_dst, act)

        # install ifunc -> ofs flows
        match_tcp_src = gen_match (ifunc.porta, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (ifunc.porta, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (ifunc.porta, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (ifunc.porta, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (self.ofs.porta)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_dst, act)

        match_tcp_src = gen_match (ifunc.portb, tcp, ifunc.iport, "src")
        match_tcp_dst = gen_match (ifunc.portb, tcp, ifunc.iport, "dst")
        match_udp_src = gen_match (ifunc.portb, udp, ifunc.iport, "src")
        match_udp_dst = gen_match (ifunc.portb, udp, ifunc.iport, "dst")
        act = [parser.OFPActionOutput (self.ofs.portb)]
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_tcp_dst, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_src, act)
        self.send_flowmod (datapath, PRIO_INJECT_FLOW, match_udp_dst, act)

        return


    def remove_inject_flows (self, datapath, ifunc) :
        
        # remove inject flows
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install ofs -> ifunc flows
        def gen_match (ip_proto, ifunc_port, portdirect) :
            
            if ip_proto == inet.IPPROTO_TCP :
                if portdirect == "src" :
                    m = parser.OFPMatch (eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         tcp_src = ifunc_port)
                elif portdirect == "dst" :
                    m = parser.OFPMatch (eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         tcp_dst = ifunc_port)
            elif ip_proto == inet.IPPROTO_UDP :
                if portdirect == "src" :
                    m = parser.OFPMatch (eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         udp_src = ifunc_port)
                elif portdirect == "dst" :
                    m = parser.OFPMatch (eth_type = ether.ETH_TYPE_IP,
                                         ip_proto = ip_proto,
                                         udp_dst = ifunc_port)
            return m

        match_tcp_src = gen_match (inet.IPPROTO_TCP, ifunc.iport, "src")
        match_tcp_dst = gen_match (inet.IPPROTO_TCP, ifunc.iport, "dst")
        match_udp_src = gen_match (inet.IPPROTO_UDP, ifunc.iport, "src")
        match_udp_dst = gen_match (inet.IPPROTO_UDP, ifunc.iport, "dst")

        self.send_flowdel (datapath, match_tcp_src)
        self.send_flowdel (datapath, match_tcp_dst)
        self.send_flowdel (datapath, match_udp_src)
        self.send_flowdel (datapath, match_udp_dst)

        return


    def install_flows (self, datapath) :

        logging.info ("install default port-a.ofs <-> port-b.ofs flows.")
        self.install_default_flows (datapath)

        for ifunc in self.ifuncs :
            if ifunc.attached :
                logging.info ("install function \"%s\" flows." % ifunc.name)
                self.install_inject_flows (datapath, ifunc)
        return


    def remove_flows (self, datapath) :

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install DEL with * match
        #match = parser.OFPMatch (in_port = self.ofs.porta)
        match = parser.OFPMatch ()
        self.send_flowdel (datapath, match)
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


    def send_flowdel (self, datapath, match) :

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        mod = parser.OFPFlowMod (datapath = datapath, 
                                 match = match,
                                 out_port = ofproto.OFPP_ANY,
                                 out_group = ofproto.OFPG_ANY,
                                 command = ofproto.OFPFC_DELETE)
        datapath.send_msg (mod)

        return


    @set_ev_cls (ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler (self, ev) :

        dpid = ev.msg.datapath.id

        if self.ofs.dpid != dpid :
            return

        logging.info ("Switch [%d] is connected." % dpid)
        self.ofs.datapath = ev.msg.datapath
        self.ofs.present = True

        # XXX: remove all enries, and install flow entries.
        self.remove_flows (ev.msg.datapath)
        self.install_flows (ev.msg.datapath)
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



class RestApi (ControllerBase) :
    
    def __init__ (self, body, link, data, **config) :
        super (RestApi, self).__init__ (body, link, data, **config)
        self.inject = data['inject']
        return


    def attach_ifunc (self, req, ifunc_name, ** _kwargs) :

        logging.info ("attach %s" % ifunc_name)

        ifunc = self.inject.find_ifunc (ifunc_name)

        if not ifunc :
            jsondict = { "error" : "invalid function %s." % ifunc_name }
            return Response (content_type = "application/json",
                             body = json.dumps (jsondict, indent = 4))

        if ifunc.attached :
            jsondict = { "error" : "function is already attached." }
            return Response (content_type = "application/json",
                             body = json.dumps (jsondict, indent = 4))

        self.inject.install_inject_flows (self.inject.ofs.datapath, ifunc)
        ifunc.attached = True

        jsondict = { "success" : "%s is attached." % ifunc_name }
        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))


    def detach_ifunc (self, req, ifunc_name, ** _kwargs) :

        logging.info ("attach %s" % ifunc_name)

        ifunc = self.inject.find_ifunc (ifunc_name)

        if not ifunc :
            jsondict = { "error" : "invalid function %s." % ifunc_name }
            return Response (content_type = "application/json",
                             body = json.dumps (jsondict, indent = 4))

        if not ifunc.attached :
            jsondict = { "error" : "function is already detached." }
            return Response (content_type = "application/json",
                             body = json.dumps (jsondict, indent = 4))

        self.inject.remove_inject_flows (self.inject.ofs.datapath, ifunc)
        ifunc.attached = False

        jsondict = { "success" : "%s is detached." % ifunc_name }
        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))


    def install_all_flows (self, req, ** _kwargs) :

        logging.info ("install all flows.")
    
        self.inject.install_flows (self.inject.ofs.datapath)

        jsondict = { "success" : "flows are installed." }
        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))


    def remove_all_flows (self, req, ** _kwargs) :
        
        logging.info ("remove all flows.")

        self.inject.remove_flows (self.inject.ofs.datapath)

        jsondict = { "success" : "flows are removed." }
        return Response (content_type = "application/json",
                         body = json.dumps (jsondict, indent = 4))
        

    def list_ifuncs (self, req, ** _kwargs) :

        logging.info ("list ifuncs.")

        ifuncs = []

        for ifunc in self.inject.ifuncs :
            ifuncjson = { 'name' : ifunc.name,
                          'porta' : ifunc.porta,
                          'portb' : ifunc.portb,
                          'iport' : ifunc.iport,
                          'attached' : ifunc.attached,
                          }
            ifuncs.append (ifuncjson)

        return Response (content_type = "application/json",
                         body = json.dumps (ifuncs, indent = 4))
