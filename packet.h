#ifndef PACKET_H
#define PACKET_H
#define MAX_LENGTH 256

#include <iostream>

using namespace std;

class Packet
{
private:
    u_char *pkt[MAX_LENGTH];
public:
    Packet();
};

char* getAttackerMAC(char *);

#endif // PACKET_H
