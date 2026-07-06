"""Pare-feu SDN pour controleur POX.

Lit les regles de restriction depuis firewallpolicies.csv et les installe
comme entrees de flux "drop" (priorite 1000) sur le commutateur OpenFlow.
Une regle par defaut (priorite 0) laisse passer tout autre trafic.

Criteres de filtrage supportes (chaque champ accepte le joker '*') :
  - adresses IP source / destination   (nw_src / nw_dst)
  - adresses MAC source / destination  (dl_src / dl_dst)
  - ports source / destination         (tp_src / tp_dst)
  - protocole : ICMP, TCP, UDP, ou ALL (tous protocoles)
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import EventMixin
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
import pox.lib.packet as pkt
import os
import csv

log = core.getLogger()
policyFile = os.path.join(os.path.dirname(__file__), "firewallpolicies.csv")


class Firewall(EventMixin):

    def __init__(self):
        self.listenTo(core.openflow)
        log.info("Enabling Firewall Module")
        self.firewall = {}

    def get_protocol_number(self, protocol):
        """Traduit le nom du protocole en numero IP. None = tous les protocoles."""
        protocol = protocol.upper()
        if protocol == "TCP":
            return pkt.ipv4.TCP_PROTOCOL
        elif protocol == "UDP":
            return pkt.ipv4.UDP_PROTOCOL
        elif protocol == "ICMP":
            return pkt.ipv4.ICMP_PROTOCOL
        elif protocol in ("ALL", "*"):
            return None
        else:
            raise ValueError("Unknown protocol: %s" % protocol)

    def sendRule(self, rule, duration=0):
        """Construit le match OpenFlow depuis la regle CSV et installe le flux drop."""
        if not isinstance(duration, tuple):
            duration = (duration, duration)
        msg = of.ofp_flow_mod()
        match = of.ofp_match()

        # Filtrage par adresse MAC (couche 2)
        if rule['src_mac'] != '*':
            match.dl_src = EthAddr(rule['src_mac'])
        if rule['dst_mac'] != '*':
            match.dl_dst = EthAddr(rule['dst_mac'])

        # Filtrage par adresse IP (couche 3) : necessite dl_type IPv4
        needs_ip = (rule['src_ip'] != '*' or rule['dst_ip'] != '*'
                    or rule['src_port'] != '*' or rule['dst_port'] != '*'
                    or rule['protocol'].upper() not in ("ALL", "*"))
        if needs_ip:
            match.dl_type = 0x800
            if rule['src_ip'] != '*':
                match.nw_src = IPAddr(rule['src_ip'])
            if rule['dst_ip'] != '*':
                match.nw_dst = IPAddr(rule['dst_ip'])
            proto = self.get_protocol_number(rule['protocol'])
            if proto is not None:
                match.nw_proto = proto
            # Filtrage par port (couche 4) : necessite un protocole TCP/UDP
            if rule['src_port'] != '*':
                match.tp_src = int(rule['src_port'])
            if rule['dst_port'] != '*':
                match.tp_dst = int(rule['dst_port'])

        msg.match = match
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.priority = 1000  # prioritaire sur la regle par defaut (0)
        # Aucune action ajoutee => le paquet correspondant est supprime (drop)
        self.connection.send(msg)

    def AddRule(self, rule):
        key = (rule['src_ip'], rule['dst_ip'], rule['src_mac'], rule['dst_mac'],
               rule['src_port'], rule['dst_port'], rule['protocol'])
        if key in self.firewall:
            log.info("Rule already present: %s", str(key))
        else:
            log.info("Adding firewall rule: src_ip %s - dst_ip %s - src_mac %s - "
                     "dst_mac %s - src_port %s - dst_port %s - protocol %s",
                     rule['src_ip'], rule['dst_ip'], rule['src_mac'], rule['dst_mac'],
                     rule['src_port'], rule['dst_port'], rule['protocol'])
            self.firewall[key] = True
            self.sendRule(rule, 10000)

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection

        with open(policyFile, "r") as ifile:
            reader = csv.DictReader(ifile)
            for row in reader:
                self.AddRule(row)

        # Regle par defaut : autoriser tout autre trafic (priorite 0)
        msg = of.ofp_flow_mod()
        msg.priority = 0
        msg.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        self.connection.send(msg)

        log.info("Firewall rules installed on %s", dpidToStr(event.dpid))


def launch():
    core.registerNew(Firewall)
