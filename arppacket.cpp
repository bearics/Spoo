#include "arppacket.h"


using namespace std;

ArpPacket::ArpPacket() :  eth(0), arp(0)
{
    *pkt={};
    setArpFormat();
}

void ArpPacket::setArpFormat()
{
    eth=(struct ether_header *)pkt;
    eth->ether_type=htons(ETHERTYPE_ARP);
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    arp->arp_hrd = htons(ARPHRD_ETHER);
    arp->arp_pro = htons(ETHERTYPE_IP);
    arp->arp_hln = ETHER_ADDR_LEN;
    arp->arp_pln = sizeof(struct in_addr);
}

void ArpPacket::setEtherDestMac(u_char * mac)
{
    eth=(struct ether_header *)pkt;
    ether_aton_r((char*)mac, (struct ether_addr *)eth->ether_dhost);
}
void ArpPacket::setEtherSourceMac(u_char * mac)
{
    eth=(struct ether_header *)pkt;
    ether_aton_r((char*)mac, (struct ether_addr *)eth->ether_shost);
}

void ArpPacket::setArpOpcode(int opcode)
{
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    arp->arp_op  = htons(ARPOP_REQUEST);
}

void ArpPacket::setArpSenderMac(u_char * mac)
{
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    ether_aton_r((char*)mac, (struct ether_addr *)arp->arp_sha);
}
void ArpPacket::setArpSenderIP(u_char * ip)
{
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    inet_pton(AF_INET, (char *)ip, arp->arp_spa);
}
void ArpPacket::setArpTargetMac(u_char * mac)
{
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    ether_aton_r((char*)mac, (struct ether_addr *)arp->arp_tha);
}
void ArpPacket::setArpTargetIP(u_char * ip)
{
    arp=(struct ether_arp *)(pkt+ETH_HLEN);
    inet_pton(AF_INET, (char *)ip, arp->arp_tpa);
}

