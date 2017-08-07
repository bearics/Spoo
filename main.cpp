#include <QCoreApplication>
#include <iostream>
#include <fstream>
#include <stdio.h>

// Add class made by bearics
#include "arppacket.h"

using namespace std;

int getAttackerInfo(u_char* ip, u_char* mac);

int main(int argc, char *argv[])
{
    u_char attackerIP[16];     // 255.255.255.255 = 15+1
    u_char attackerMAC[18];    // FF:FF:FF:FF:FF:FF = 17+1


    getAttackerInfo(attackerIP, attackerMAC);

    cout << "Attacker's IP : " << attackerIP <<endl;
    cout << "Attacker's MAC : " << attackerMAC<<endl;

    return 0;
}

int getAttackerInfo(u_char* attackerIP, u_char* attackerMAC)
{
    FILE *fp;

    fp = popen( "ifconfig | grep -A3 \"inet\" | sed -n 1p | awk '{print $2}'", "r");
    fscanf(fp, "%s", attackerIP);
    pclose(fp);

    fp = popen( "ifconfig | grep -A3 \"inet\" | sed -n 3p | awk '{print $2}'", "r");
    fscanf(fp, "%s", attackerMAC);
    pclose(fp);

    return 0;
}
