#include "arp_spoofing.h"


u_int32_t splitIP(char* ip){
    u_int32_t split_ip = 0;
    u_int8_t i = 24;
    char* ptr = nullptr;
    ptr = strtok(ip,".");
    split_ip = static_cast<u_int32_t>(atoi(ptr) << i);
    while(ptr != nullptr){
        i = i - 8;
        ptr = strtok(nullptr,".");
        split_ip = split_ip | static_cast<u_int32_t>(atoi(ptr) << i);
        if(i == 0) break;
    };
    return split_ip;
}
void makeArpPacketSection(vector<ST_arp_section>* v, u_char* mac, u_int32_t ip , u_int32_t sender, u_int32_t target){
    ST_je_arp_header arp;
    ST_arp_section section;
    //set ethernet_broadcast
    memset(&arp.eth_hdr.ether_dhost, 0xff, sizeof(arp.eth_hdr.ether_dhost));
    //host_Mac_IP and senderMAC
    for(int z = 0; z < 6; z++){
        arp.eth_hdr.ether_shost[z] = mac[z];
        arp.sender_mac[z] = mac[z];
    }
    //arp_type
    arp.eth_hdr.ether_type = htons(ETHERTYPE_ARP);
    //arp hdr
    arp.arp_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.arp_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp.arp_hdr.ar_hln = 0x06;
    arp.arp_hdr.ar_pln = 0x04;
    arp.arp_hdr.ar_op = htons(ARPOP_REQUEST);

    //targeterMAc
    memset(&arp.target_mac, 0x00, sizeof(arp.target_mac));

    //senderIP and targeterIP
    arp.sender_ip_addr.s_addr = ip;
    arp.target_ip_addr.s_addr = sender;
    section.sernder = arp;
    section.sendercheck = 0;
    section.senderCrrentTime = 0;
    arp.target_ip_addr.s_addr = target;
    section.target = arp;
    section.targetcehck = 0;
    section.targetCrrentTime = 0;
    (*v).push_back(section);
}
void packetInsert(u_char* packet, ST_je_arp_header** arp_header){
    *arp_header = reinterpret_cast<ST_je_arp_header*>(packet);
    (*arp_header)->eth_hdr.ether_type =  ntohs((*arp_header)->eth_hdr.ether_type);
    (*arp_header)->arp_hdr.ar_hrd = ntohs((*arp_header)->arp_hdr.ar_hrd);
    (*arp_header)->arp_hdr.ar_pro = ntohs((*arp_header)->arp_hdr.ar_pro);
    (*arp_header)->arp_hdr.ar_op = ntohs((*arp_header)->arp_hdr.ar_op);
    (*arp_header)->sender_ip_addr.s_addr = (*arp_header)->sender_ip_addr.s_addr;
    (*arp_header)->target_ip_addr.s_addr = (*arp_header)->target_ip_addr.s_addr;
}
void packetInsert(u_char* packet, ST_je_ip_header** ip_header){
    *ip_header = reinterpret_cast<ST_je_ip_header*>(packet);
}
void printfJeArpInfo(ST_je_arp_header* arp_header){
    printf("D_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->eth_hdr.ether_dhost[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->eth_hdr.ether_dhost[i+1]);
            break;
        }
    }
    printf("S_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->eth_hdr.ether_shost[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->eth_hdr.ether_shost[i+1]);
            break;
        }
    }
    printf("ETH_TYPE %x\r\n", arp_header->eth_hdr.ether_type);
    printf("HW_TYPE %x\r\n", arp_header->arp_hdr.ar_hrd);
    printf("PRO_TYPE %x\r\n", arp_header->arp_hdr.ar_pro);
    printf("HW_SIZE %x\r\n", arp_header->arp_hdr.ar_hln);
    printf("PRO_SIZE %x\r\n", arp_header->arp_hdr.ar_pln);
    printf("PRO_TYPE %x\r\n", arp_header->arp_hdr.ar_op);

    printf("Send_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->sender_mac[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->sender_mac[i+1]);
            break;
        }
    }
    printf("Sender : %d.%d.%d.%d \r\n", (arp_header->sender_ip_addr.s_addr & 0xff000000) >> 24  , (arp_header->sender_ip_addr.s_addr & 0x00ff0000) >> 16 , (arp_header->sender_ip_addr.s_addr & 0x0000ff00) >> 8 , arp_header->sender_ip_addr.s_addr & 0x000000ff);
    printf("target_Mac  ");
    for (int i = 0; i < 5; i++) {
        printf("%02x:", arp_header->target_mac[i]);
        if(i==4){
            printf("%02x\r\n", arp_header->target_mac[i+1]);
            break;
        }
    }
    printf("Target : %d.%d.%d.%d\r\n", (arp_header->target_ip_addr.s_addr & 0xff000000) >> 24  , (arp_header->target_ip_addr.s_addr & 0x00ff0000) >> 16 , (arp_header->target_ip_addr.s_addr & 0x0000ff00) >> 8 , arp_header->target_ip_addr.s_addr & 0x000000ff);

}
void printfPacket(const u_char* packet, u_int lenght ){
    for (int i = 0 ; i < static_cast<int>(lenght); i++) {
        printf("%02x ",packet[i]);
        if( (i + 1) % 16 == 0){
            printf("\r\n");
        }
    }
    printf("\r\n");
}
