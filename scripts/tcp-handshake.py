#!/usr/bin/python

from random import randint
from scapy.all import *
from machines import attacker as bob
from machines import target as alice

_syn_ip = IP(src=bob.ip, dst=alice.ip)
_syn_tcp = TCP(dport=80, sport=1337, flags="S", seq=1337)
syn = _syn_ip/_syn_tcp
print("SYN :\n")
print(syn.show())

synack = sr1(syn)
print("SYN ACK :\n")
print(synack.show())

_ack_ip = IP(src=bob.ip, dst=alice.ip)
_ack_tcp = TCP(dport=80, sport=1337, flags='A', seq=1338, ack=synack.ack)
ack = _ack_ip/_ack_tcp
print("ACK :\n")
print(ack.show())
send(ack)
