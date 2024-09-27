from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr
import pox.lib.packet as pkt
import os
import csv

log = core.getLogger()
policyFile = os.path.join(os.path.dirname(__file__), "firewallpolicies.csv")

class Firewall (EventMixin):

    def __init__ (self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        self.firewall = {}


    def sendRule(self, src_ip, dst_ip, src_port, dst_port, protocol, duration=0):
        if not isinstance(duration, tuple):
            duration = (duration, duration)
        msg = of.ofp_flow_mod()
        match = of.ofp_match()
        match.dl_type = 0x800  
        match.nw_src = IPAddr(src_ip)
        match.nw_dst = IPAddr(dst_ip)
        if src_port != '*':
            match.tp_src = int(src_port)
        if dst_port != '*':
            match.tp_dst = int(dst_port)
        match.nw_proto = self.get_protocol_number(protocol)
        msg.match = match
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 1000
        self.connection.send(msg)
    def get_protocol_number(self, protocol):
        if protocol == "TCP":
            return pkt.ipv4.TCP_PROTOCOL
        elif protocol == "UDP":
            return pkt.ipv4.UDP_PROTOCOL
        elif protocol == "ICMP":
            return pkt.ipv4.ICMP_PROTOCOL
        else:
            raise ValueError("Unknown protocol: %s" % protocol)

    def AddRule(self, src_ip, dst_ip, src_port, dst_port, protocol):
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        if key in self.firewall:
            log.info("Rule already present: src %s - dst %s - src_port %s - dst_port %s - protocol %s", src_ip, dst_ip, src_port, dst_port, protocol)
        else:
            log.info("Adding firewall rule: src %s - dst %s - src_port %s - dst_port %s - protocol %s", src_ip, dst_ip, src_port, dst_port, protocol)
            self.firewall[key] = True
            self.sendRule(src_ip, dst_ip, src_port, dst_port, protocol, 10000)

    def DeleteRule(self, src_ip, dst_ip, src_port, dst_port, protocol):
        key = (src_ip, dst_ip, src_port, dst_port, protocol)
        try:
            del self.firewall[key]
            self.sendRule(src_ip, dst_ip, src_port, dst_port, protocol, 0)
            log.info("Deleting firewall rule: src %s - dst %s - src_port %s - dst_port %s - protocol %s", src_ip, dst_ip, src_port, dst_port, protocol)
        except KeyError:
            log.error("Cannot find rule: src %s - dst %s - src_port %s - dst_port %s - protocol %s", src_ip, dst_ip, src_port, dst_port, protocol)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection

        with open(policyFile, "r") as ifile:
            reader = csv.DictReader(ifile)
            for row in reader:
                self.AddRule(row['src_ip'], row['dst_ip'], row['src_port'], row['dst_port'], row['protocol'])

        # Add a default rule to allow all other traffic
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        self.connection.send(msg)

        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))

def launch():
    core.registerNew(Firewall)