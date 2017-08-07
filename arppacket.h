#ifndef PACKET_H
#define PACKET_H
#define MAX_LENGTH 42

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iostream>

using namespace std;

class ArpPacket
{
private:
    u_char pkt[MAX_LENGTH];
    struct ether_header *eth;
    struct ether_arp *arp;
public:
    Packet();
    Packet(u_char *ip);
    void setEtherSenderMac(u_char * mac);
    void setEtherRecieverMac(u_char * mac);
    void setArpSenderIP(u_char * ip);
    void setArpRecieverIP(u_char * ip);
};

#endif // PACKET_H
