#include <pcap.h>  
#include <arpa/inet.h>  
#include <time.h>  
#include <stdlib.h>  
#include <string.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define BUFSIZE 10240
#define MAX_URL_LEN 2048
#define MAX_GET_LEN 2048
#define MAX_HOST_LEN 1024

#define get_u_int16_t(X,O)  (*(uint16_t *)(((uint8_t *)X) + O))

int count = 0;

void ethernet_protocol_callback(unsigned char *argument,const struct pcap_pkthdr *packet_header,const unsigned char *packet_content)  
{   
	count++;
    	if(count == 10000) {
		printf("%d\n",count);
        	count = 0;
    	}
    
	struct ethhdr *ether_header = (struct ethhdr*)packet_content; 
    	struct iphdr *ip_header = (struct iphdr*)(packet_content + sizeof(struct ethhdr));
    	struct tcphdr *tcp_header = (struct tcphdr*)(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	char payload[MAX_GET_LEN];
    	
	struct in_addr addr;

    	u_int16_t ether_type = ntohs(ether_header->h_proto);  
    	switch(ether_type)  
    	{  
        	case 0x0800:
	    		addr.s_addr = ip_header->saddr;
	    		char srcIP[32];
	    		strcpy(srcIP, inet_ntoa(addr));

	    		addr.s_addr = ip_header->daddr;
	    		char dstIP[32];
	    		strcpy(dstIP, inet_ntoa(addr)); 

            		u_int32_t payload_offset = sizeof(struct ethhdr);
	    		payload_offset += sizeof(struct iphdr);
	    		payload_offset += (tcp_header->doff << 2); 
			        
	    		int payload_len = packet_header->len - payload_offset;
			memcpy(payload, packet_content+payload_offset, payload_len);
	    		//const unsigned char *payload = packet_content + payload_offset;
			payload[payload_len] = '\0';

    	    		/*filter get packet*/
            		if(memcmp(payload, "GET ", 4)) 
			{
				return;
            		}		
	    
	    		int line_len;
            		int hstrlen; //"host: " 
            		int hostlen;
            		char host[MAX_HOST_LEN];
            		int a, b;
    
    	    		for(a = 0, b = 0; a < payload_len - 1; a++) 
			{
        			if (get_u_int16_t(payload, a) == ntohs(0x0d0a)) 
				{
                    			line_len = (u_int16_t)(((unsigned long) &payload[a]) - ((unsigned long)&payload[b]));
    
            	    			if (line_len > 6 && memcmp(&payload[b], "Host:", 5) == 0) 
					{
                				if(*(payload + b + 5) == ' ') 
						{
                            				hstrlen = b + 6;
                				} 
						else
						{
                    	    				hstrlen = b + 5;
                				}

               	 				hostlen = a - hstrlen;   
                				memcpy(host, payload + hstrlen, (a - hstrlen));
						host[hostlen] = '\0';
            	    			}	   
            
		    			b = a + 2;
        			}	   
    	    		}		

            		char url[MAX_URL_LEN];
    	    		memcpy(url, host, hostlen);
	    		url[hostlen] = '\0';

	    		//printf("%s\n",payload);
	    		//printf("\n----------------------------------------------------\n");  
	    		//printf("%s\n", ctime((time_t *)&(packet_header->ts.tv_sec)));   
            		//printf("SrcIP and SrcPort is %s:%d\n",srcIP,ntohs(tcp_header->source));
	    		//printf("DstIP and DstPort is %s:%d\n",dstIP,ntohs(tcp_header->dest));
 	    		//printf("host is %s\n", host);
			
			unsigned char resp_packet[MAX_GET_LEN];
			const char *resp_payload= "HTTP/1.1 302 FOUND\r\nServer: nginx/1.1.15\r\nContent-Type: text/html; charset=utf-8\r\nConnection: keep-alive\r\nLocation: http://www.qq.com/\r\n\r\n";
		
			
			int resp_offset = 0;
			
			memcpy(resp_packet + resp_offset, ether_header, sizeof(struct ethhdr));
			resp_offset += sizeof(struct ethhdr);
			memcpy(resp_packet, ether_header->h_source, ETH_ALEN);
			memcpy(resp_packet + ETH_ALEN, ether_header->h_dest, ETH_ALEN);

			struct ethhdr *resp_ether_header = (struct ethhdr*)resp_packet;
			printf("%s  %d  %d\n", resp_ether_header->h_dest, ntohs(resp_ether_header->h_proto), ether_type);	
		
            		break;//ip  
        	case 0x0806:
			break;//arp  
        	case 0x0835:
			break;//rarp  
        	default:
			break;  
    	}  
}  
  
int main(int argc, char *argv[])  
{  
    	char error_content[100];     
    	pcap_t * pcap_handle;  
    	pcap_handle = pcap_open_live("em1",BUFSIZE,1,0,error_content);  
          
    	struct bpf_program filter;
    	pcap_compile(pcap_handle, &filter, "ip and tcp and dst port 80", 1, 0);
    	pcap_setfilter(pcap_handle, &filter);

    	if(pcap_loop(pcap_handle,-1,ethernet_protocol_callback,NULL) < 0)  
    	{	  
        	perror("pcap_loop");  
    	}  
      
    	pcap_close(pcap_handle);  
    	return 0;  
}
