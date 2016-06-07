#include "stdafx.h"
#include <time.h>
#include "windivert.h"

#define MAX_PACKET_SIZE 1500

BOOL debug = FALSE;
BOOL debug2 = FALSE;

#define ETHER_ADDR_LEN 6
struct ethernet_header {
	UCHAR ether_dhost[ETHER_ADDR_LEN];    // destination host address
	UCHAR  ether_shost[ETHER_ADDR_LEN];    // source host address
	USHORT ether_type;                     // IP? ARP? RARP? etc
};

/* 4 bytes IP address */
typedef struct ip_address {
	UCHAR byte1;
	UCHAR byte2;
	UCHAR byte3;
	UCHAR byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header {
	UCHAR  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	UCHAR  tos;            // Type of service 
	USHORT tlen;           // Total length 
	USHORT identification; // Identification
	USHORT flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	UCHAR  ttl;            // Time to live
	UCHAR  proto;          // Protocol
	USHORT crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	UINT   op_pad;         // Option + Padding
} ip_header;

VOID debug_print(CONST CHAR * format, ...)
{
	if (debug)
	{
		time_t     now = time(NULL);
		struct tm  tstruct;
		CHAR      buf[21];

		localtime_s(&tstruct, &now);
		strftime(buf, sizeof(buf), "%Y-%m-%d %X ", &tstruct);
		printf("%s", buf);

		va_list args;
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}

VOID usage()
{
	printf("\nIPIPReceiver:\n"
		" receives IPinIP packets from network, then\n"
		" extracts IP packet and send it back to OS.\n"
		"Usage:\n"
		" IPIPReceiver [options]\n"
		"Options:\n"
		" -h         display this help\n"
		" -d         turn on debugging\n"
		" -d -d      debugging + hex dump packets\n");
}

/* Decapsulate an IPIP packet */
VOID process_ipip_packet(CONST UCHAR *payload, UCHAR *new_packet_payload) {

	UINT ip_hl;
	CONST UCHAR *payload_src = NULL;
	UCHAR *payload_dst = NULL;
	CONST struct ip_header *ip_hdr = NULL;

	payload_src = payload;
	payload_dst = new_packet_payload;

	// Read encapsulating IP header to find offset to encapsulted IP packet
	ip_hdr = (CONST struct ip_header *) payload_src;

	// Shift to encapsulated IP header, read total length
	ip_hl = (ip_hdr->ver_ihl & 0xf) * 4;
	payload_src += ip_hl;
	ip_hdr = (CONST struct ip_header *) payload_src;

	memcpy(payload_dst, payload_src, ntohs(ip_hdr->tlen));
}

/* Print the hex values of the data */
VOID print_hex(CONST UCHAR* data, SIZE_T Size)
{
	UCHAR a, line[17], c;
	SIZE_T i, j;

	//loop over each CHARacter and print
	for (i = 0; i < Size; i++)
	{
		c = data[i];
		//Print the hex value for every CHARacter , with a space
		printf(" %.2x", (UINT)c);
		//Add the CHARacter to data line
		a = (c >= 32 && c <= 128) ? (UCHAR)c : '.';
		line[i % 16] = a;
		//if last CHARacter of a line , then print the line - 16 CHARacters in 1 line
		if ((i != 0 && (i + 1) % 16 == 0) || i == Size - 1)
		{
			line[i % 16 + 1] = '\0';
			//print a big gap of 10 CHARacters between hex and CHARacters
			printf("          ");
			//Print additional spaces for last lines which might be less than 16 CHARacters in length
			for (j = (SIZE_T)strlen((CONST CHAR*)line); j < 16; j++)
			{
				printf("   ");
			}
			printf("%s \n", line);
		}
	}
	printf("\n");
}

/* Thread for capturing and processing packets */
VOID packet_handler(LPVOID arg, bool child=TRUE)
{
	UCHAR pkt_data[MAX_PACKET_SIZE];
	UINT pkt_size, out_pkt_size = 0;
	WINDIVERT_ADDRESS wd_addr;
	HANDLE handle = (HANDLE)arg;

	CONST struct ip_header *ip_hdr = NULL;

	if (!(child))
	{
		printf("Main thread has been started.\n");
	}

	UCHAR *out_pkt_data = (UCHAR *)malloc(MAX_PACKET_SIZE);
	if (out_pkt_data == NULL) {
		printf("Cannot allocate memory! Requested %d bytes.\n", MAX_PACKET_SIZE);
		return;
	}

	// Main loop
	while (TRUE)
	{
		// Read a matching packet.
		if (!WinDivertRecv(handle, pkt_data, sizeof(pkt_data), &wd_addr, &pkt_size))
		{
			fprintf(stderr, "Warning: failed to read packet (%u)\n", GetLastError());
			continue;
		}

		if (debug)
		{
			ip_hdr = (CONST struct ip_header *)pkt_data;

			debug_print("IPIP in hlen:%i iplen:%02i proto:%02x %d.%d.%d.%d->%d.%d.%d.%d\n",
				((ip_hdr->ver_ihl & 0xf) * 4), ntohs(ip_hdr->tlen), ip_hdr->proto,
				ip_hdr->saddr.byte1, ip_hdr->saddr.byte2, ip_hdr->saddr.byte3, ip_hdr->saddr.byte4,
				ip_hdr->daddr.byte1, ip_hdr->daddr.byte2, ip_hdr->daddr.byte3, ip_hdr->daddr.byte4);

			if (debug2)
				// Print the packet
				print_hex(pkt_data, (SIZE_T)pkt_size);
		}

		process_ipip_packet(pkt_data, out_pkt_data);

		ip_hdr = (CONST struct ip_header *)out_pkt_data;

		debug_print("IP  out hlen:%i iplen:%02i proto:%02x %d.%d.%d.%d->%d.%d.%d.%d\n",
			((ip_hdr->ver_ihl & 0xf) * 4), ntohs(ip_hdr->tlen), ip_hdr->proto,
			ip_hdr->saddr.byte1, ip_hdr->saddr.byte2, ip_hdr->saddr.byte3, ip_hdr->saddr.byte4,
			ip_hdr->daddr.byte1, ip_hdr->daddr.byte2, ip_hdr->daddr.byte3, ip_hdr->daddr.byte4);

		out_pkt_size = ntohs(ip_hdr->tlen);// +sizeof(struct ethernet_header);

		if (debug2)
			// Print the packet
			print_hex(out_pkt_data, out_pkt_size);

		// Send decapsulated packet
		if (!WinDivertSend(handle, out_pkt_data, out_pkt_size, &wd_addr, NULL))
		{
			fprintf(stderr, "Error sending the packet: %u\n", GetLastError());
		}
	}
	free(out_pkt_data);
}

INT main(INT argc, CHAR **argv)
{
	SIZE_T i, num_threads = 4;
	HANDLE handle, thread;

	for (i = 1; i < (SIZE_T)argc; i++)
	{
		switch (argv[i][1])
		{
		case 'd':
		{
			if (!debug)
			{
				debug = TRUE;
				debug_print("Debug enabled.\n");
			}
			else
			{
				debug2 = TRUE;
				debug_print("Packet dump enabled.\n");
			}
		}
		break;
		}
	}

	for (i = 1; i < (SIZE_T)argc; i++)
	{
		switch (argv[i][1])
		{
			case 'h':
			{
				usage();
				return 0;
			}
			break;
		}
		switch (argv[i][1])
		{
			case 'n':
			{
				i++;
				num_threads = atoi(argv[i]);
			}
			break;
		}
	}

	printf("Starting capture.\n");

	// Divert traffic matching the filter:
	handle = WinDivertOpen("inbound and ip.Protocol == 4", WINDIVERT_LAYER_NETWORK, 0, 0);
	if (handle == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER)
		{
			fprintf(stderr, "Error setting filter.\n");
			exit(EXIT_FAILURE);
		}
		fprintf(stderr, "Error opening WinDivert device (%u)\n", GetLastError());
		exit(EXIT_FAILURE);
	}
	else
		debug_print("Network device successfully opened.\n");

	// Start the threads
	printf("Starting threads.\n");

	if (!(debug))
	{
		for (i = 1; i < num_threads; i++)
		{
			thread = CreateThread(NULL, 1, (LPTHREAD_START_ROUTINE)packet_handler, (LPVOID)handle, 0, NULL);
			if (thread == NULL)
			{
				fprintf(stderr, "Failed to start %Iu thread (%u)\n", i, GetLastError());
				exit(EXIT_FAILURE);
			}
			else
			{
				printf("Thread #%Iu has been started.\n", i);
			}
		}
	}
	else
		debug_print("Multithreading disabled in debug mode.\n");

	// Main thread:
	packet_handler((LPVOID)handle, FALSE);

	printf("Terminating application.\n");

	return 0;
}
