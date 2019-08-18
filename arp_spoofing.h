#pragma once

/*-------------------------- include ------------------------------------*/
#include <libnet.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/types.h>
#include <string.h>
#include <pthread.h>
#include <vector>
#include <string.h>

using namespace std;

/*-------------------------- struct ------------------------------------*/
#pragma pack(1)
struct ST_je_ip_header{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_ipv4_hdr ip_hdr;
};

#pragma pack(1)
struct ST_je_arp_header{
    struct libnet_ethernet_hdr eth_hdr;
    struct libnet_arp_hdr arp_hdr;
    uint8_t sender_mac[ETHER_ADDR_LEN];
    struct in_addr sender_ip_addr;
    uint8_t target_mac[ETHER_ADDR_LEN];
    struct in_addr target_ip_addr;
};

struct ST_arp_section{
    struct ST_je_arp_header sernder;
    struct ST_je_arp_header target;
    int sendercheck;
    int targetcehck;
    time_t senderCrrentTime;
    time_t targetCrrentTime;
};



/*-------------------------- Function ------------------------------------*/
u_int32_t splitIP(char* ip);
void makeArpPacketSection(vector<ST_arp_section>* v, u_char* mac, u_int32_t ip , u_int32_t sender, u_int32_t target);
void setSplitIP(char* ip, u_char* packet);
void printfPacket(const u_char* packet, u_int lenght);
void packetInsert(u_char* packet, ST_je_arp_header** arp_header);
void packetInsert(u_char* packet, ST_je_ip_header** ip_header);
void printfJeArpInfo(ST_je_arp_header* arp_header);
