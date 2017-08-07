#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

void getAttackerInfo(u_char* ip, u_char* mac);
void sendPkt(pcap_t *handle, u_char* send_pkt, int size);

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    //struct bpf_program fp;		/* The compiled filter */
    //char filter_exp[] = "port ";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    //struct pcap_pkthdr *header;	/* The header that pcap gives us */

    // attacker's information
    u_char attackerIP[16];     // 255.255.255.255 = 15+1
    u_char attackerMAC[18];    // FF:FF:FF:FF:FF:FF = 17+1

    getAttackerInfo(attackerIP, attackerMAC);

    cout << "Attacker's IP : " << attackerIP <<endl;
    cout << "Attacker's MAC : " << attackerMAC<<endl;

    /* Define the device */
    dev = pcap_lookupdev(errbuf);;
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device is %s\n", argv[1]);
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return(2);
    }

    ArpPacket spoof;
    spoof.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    spoof.setEtherSourceMac(attackerMAC);
    spoof.setArpOpcode(ARPOP_REQUEST);
    spoof.setArpSenderIP(attackerIP);
    spoof.setArpSenderMac(attackerMAC);
    spoof.setArpTargetIP((u_char*)argv[2]);
    spoof.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    sendPkt(handle, spoof.pkt, sizeof(spoof.pkt));
}

void getAttackerInfo(u_char* attackerIP, u_char* attackerMAC)
{
    FILE *fp;

    fp = popen( "ifconfig | grep -A3 \"inet\" | sed -n 1p | awk '{print $2}'", "r");
    fscanf(fp, "%s", attackerIP);
    pclose(fp);

    fp = popen( "ifconfig | grep -A3 \"inet\" | sed -n 3p | awk '{print $2}'", "r");
    fscanf(fp, "%s", attackerMAC);
    pclose(fp);

}

void sendPkt(pcap_t *handle, u_char* send_pkt, int size)
{
    if(pcap_sendpacket(handle, send_pkt, size) == -1)
        cout << "Sending ERROR!" << endl;
    else
        cout << "Sending SUCCESS!" << endl;
}
