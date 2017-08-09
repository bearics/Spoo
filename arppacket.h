#ifndef PACKET_H
#define PACKET_H
#define ARP_PKT_LENGTH 42

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>

using namespace std;

class ArpPacket
{
public:
    u_char pkt[ARP_PKT_LENGTH];
    struct ether_header *eth;
    struct ether_arp *arp;
    ArpPacket();
    ArpPacket(u_char *ip);
    u_char* getPkt();
    void printPkt();
    void setArpFormat();
    void setEtherDestMac(u_char * mac);
    void setEtherSourceMac(u_char * mac);
    void setArpOpcode(int opcode);
    void setArpSenderMac(u_char * mac);
    void setArpSenderIP(u_char * ip);
    void setArpTargetMac(u_char * mac);
    void setArpTargetIP(u_char * ip);
};

class MyThread : public thread
{
public:
    bool active{true};
    void close() { active = false; };
};

#endif // PACKET_H
