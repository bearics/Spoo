#include "packet.h"


using namespace std;

Packet::Packet() :  eth(0), arp(0)
{
    *pkt={};
}

int Packet::getMAC(u_char *ip)
{


    return 0;
}

int Packet::getMAC(u_char *ip)
{

}

int Packet::sendPkt(u_char* sender_ip, u_char* sender_mac, u_char* receiver_ip, u_char* receiver_mac, int opcode)
{

}


char* getMACAdr(char *IPAdr)
{
    return 0;
}
