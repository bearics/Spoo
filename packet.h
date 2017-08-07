#ifndef PACKET_H
#define PACKET_H
#define MAX_LENGTH 256

#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <iostream>

using namespace std;

class Packet
{
private:
    u_char pkt[MAX_LENGTH];
    struct ether_header *eth;
    struct ether_arp *arp;
public:
    Packet();
    Packet(u_char *ip);
    int getMAC(u_char *ip);
    int sendPkt(u_char* sender_ip, u_char* sender_mac, u_char* receiver_ip, u_char* receiver_mac, int opcode);
};

char* getAttackerMAC(char *);

#endif // PACKET_H
