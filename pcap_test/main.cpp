#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>

#define MACSIZE 6
#define IPADDRLEN 16
#define ETHERTYPEIP 0x0800
#define IPPROTOTCP 6

struct ether_header {
    unsigned char DstMACAddr[MACSIZE];
    unsigned char SrcMACAddr[MACSIZE];
    unsigned short EtherType;
};

struct ip_header {
    unsigned char Header_Length:4;
    unsigned char Version:4;
    unsigned char TOS;
    unsigned short Total_Length;
    unsigned short Identification;
    unsigned short Fragment_Offset;
    unsigned char TTL;
    unsigned char Protocol;
    unsigned short Header_Checksum;
    unsigned int SrcIPAddr;
    unsigned int DstIPAddr;
};

struct tcp_header {
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int Seq_Number;
    unsigned int Ack_Number;
    unsigned char Reserved:4;
    unsigned char Offset:4;
    unsigned char TCPFlags;
    unsigned short Window;
    unsigned short Checksum;
    unsigned short Urgent_Pointer;
};

void usage() 
{
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) 
{
  	if (argc != 2) 
	{
    	usage();
    	return -1;
  	}
	struct ether_header* ethdr;
    struct ip_header* iphdr;
    struct tcp_header* tcphdr;
    struct in_addr inaddr;
    
	char IPAddr[IPADDRLEN];
    int IPHeaderLen;
	
	char net_str[16], mask_str[16];
	unsigned int net_hex, mask_hex;
	char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];	

	printf("[*] device : %s\n", dev);
	if (pcap_lookupnet(dev, &net_hex, &mask_hex, 0) == -1) 
	{
        printf("[!] error in pcap_lookupnet()\n");
        return -1;
    }

    inaddr.s_addr = net_hex;
    printf("[*] ip address : %s\n", inet_ntop(AF_INET, &inaddr, net_str, 16));
    inaddr.s_addr = mask_hex;
    printf("[*] subnetmask address : %s\n\n", inet_ntop(AF_INET, &inaddr, mask_str, 16));

 	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) 
	{
    	fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    	return -1;
  	}
 	while (1) 
	{
		struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

    	ethdr = (struct ether_header*)packet;	
   		iphdr = (struct ip_header*)(packet + sizeof(ether_header));
    	IPHeaderLen = iphdr->Header_Length * 4;
    	tcphdr = (struct tcp_header*)((char*)iphdr + IPHeaderLen);

    	printf("[*] Receiving packet\n");
    	printf("Eth Src MAC Address : ");
    	for (int i = 0; i < MACSIZE; i++) 
        	printf("%02x:", ethdr->SrcMACAddr[i]);
    	printf("\b \n");		
    	inaddr.s_addr = iphdr->SrcIPAddr;
    	printf("Src IP Address : %s\n", inet_ntop(AF_INET, &inaddr, IPAddr, IPADDRLEN));
    	printf("Src Port : %d\n", ntohs(tcphdr->SrcPort));

    	printf("Eth Dst MAC Address : ");
    	for (int i = 0; i < MACSIZE; i++) 
        	printf("%02x:", ethdr->DstMACAddr[i]);
    	printf("\b \n");
    	inaddr.s_addr = iphdr->DstIPAddr;
    	printf("Dst IP Address : %s\n", inet_ntop(AF_INET, &inaddr, IPAddr, IPADDRLEN));
    	printf("Dst Port : %d\n", ntohs(tcphdr->DstPort));
    	printf("\n");
  	}

  	pcap_close(handle);
  	return 0;
}
