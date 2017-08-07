#include "arppacket.h"


using namespace std;

Packet::Packet() :  eth(0), arp(0)
{
    *pkt={};
}

void Packet::setEtherSenderMac(u_char * mac)
{

}

void Packet::setEtherRecieverMac(u_char * mac)
{

}

void Packet::setArpSenderIP(u_char * ip)
{

}

void Packet::setArpRecieverIP(u_char * ip)
{

}
