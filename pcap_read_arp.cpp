#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <cstdio>
#include <iostream>
#include <cstring>
#include <pcap.h>
#include <net/if_arp.h>

using namespace std;

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header);

void usage(){ //사용법 출력
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]){
    if (argc != 2){ //인자값이 2가 아니면 빠꾸
        usage();
        return -1; //0이 아니면 다 정상종료x 프로그램에서 리턴하는 경우 이렇게 아무 값이나 주는 게 좋다
    }

    char* dev = argv[1]; //argv[0]은 파일 이름, argv[1]이 데이터
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //BUFSIZ는 기본값
    if(handle==nullptr){
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf); //handle이 없으면 종료
        return -1;
    }

    while(true){ //종료 때까지
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if(res==0) continue;
        if(res==-1 || res==-2){
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        dump_pkt(packet, header);
    }
    pcap_close(handle);    
}

void dump_pkt(const u_char *pkt_data, struct pcap_pkthdr* header){
    struct ether_header *eth_hdr; //이더넷 헤더 구조체
    eth_hdr = (struct ether_header *)pkt_data; //패킷 데이터에서 이더넷 헤더 가져옴
    u_int16_t eth_type = ntohs(eth_hdr->ether_type); //이더넷 헤더에서 이더넷 타입 값을 가져와 리틀 엔디안으로 변환

    //if type is not arp, return function 이더넷 타입이 arp가 아니면 리턴
    if(eth_type!=ETHERTYPE_ARP) return;

    struct arphdr *arp_hdr = (struct arphdr *)(pkt_data+sizeof(ether_header)); //arphdr구조체 가져옴

    u_int8_t hardware_format = arp_hdr->ar_hrd; //하드웨어 포맷
    u_int8_t protocol_format = arp_hdr->ar_pro; //프로토콜 포맷

    printf("\nARP Packet Info====================================\n");

    //print pkt length
    printf("%u bytes captured. Actual length: %u\n", header->caplen, header->len); //헤더에서 캡쳐된 패킷 크기 가져와서 출력

    //print mac addr
    u_int8_t *dst_mac = eth_hdr->ether_dhost; //이더넷 헤더에서 목적지 mac주소 가져옴
    u_int8_t *src_mac = eth_hdr->ether_shost; //이더넷 헤더에서 출발지 mac주소 가져옴

    printf("Dst MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        dst_mac[0],dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]); //mac주소 출력

    printf("Src MAC : %02x:%02x:%02x:%02x:%02x:%02x\n",
        src_mac[0],src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]); //mac주소 출력
    
    //print length
    printf("Length of hardware address : %d\n", arp_hdr->ar_hln);
    printf("Length of protocol address : %d\n", arp_hdr->ar_pln);
    
    //print format
    printf("Format of hardware address : ");
    if(ntohs(arp_hdr->ar_hrd) == ARPHRD_ETHER) printf("Ethernet 10/100Mbps\n");  //Ethernet 10/100Mbps
    else printf("%x\n", ntohs(arp_hdr->ar_hrd)); //another format

    printf("ARP opcode: ");
    if(arp_hdr->ar_op == ARPOP_REQUEST) printf("ARP request\n"); //op코드가 1이면 request 패킷
    else if(arp_hdr->ar_op== ARPOP_REPLY) printf("ARP request\n"); //op코드가 2면 reply 패킷
    else if(arp_hdr->ar_op== ARPOP_RREQUEST) printf("RARP request\n"); //op코드가 3이면 rarp request패킷
    else if(arp_hdr->ar_op== ARPOP_RREPLY) printf("RARP request\n"); //op코드가 4면 rarp reply 패킷
    else printf("%x\n\n", ntohs(arp_hdr->ar_op)); //another OP code
}
