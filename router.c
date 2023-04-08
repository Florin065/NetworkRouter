#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ICMP_ECHO_REPLY 		0
#define ICMP_DEST_UNREACHABLE 	3
#define ICMP_ECHO_REQUEST 		8
#define ICMP_TIME_EXCEEDED 		11

#define ARP_OP_REQUEST 			1
#define ARP_OP_REPLY 			2

#define DROP_PACKAGE 			-1
#define GOOD_PACKAGE  			0

/* Routing table */
struct route_table_entry *rtable;
size_t rtable_len;

/* ARP table */
struct arp_entry *arp_table;
size_t arp_table_len;

struct ether_header *eth_hdr;
struct iphdr *ip_hdr;
struct icmphdr *icmp_hdr;

struct arp_entry *mac;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;

	for (size_t i = 0; i < rtable_len; i++) {
		if ((rtable[i].mask & ip_dest)
			 ==
			(rtable[i].prefix & rtable[i].mask)) {

			if (!best_route)
				best_route = &rtable[i];
			else if (best_route->mask < rtable[i].mask)
				best_route = &rtable[i];
		}
	}

	return best_route;
}

struct arp_entry *get_arp_entry(uint32_t ip_dest) {
	for (size_t i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip_dest) {
			return &arp_table[i];
		}
	}

	return NULL;
}

void icmp(int interface, int type,
		  char buf[MAX_PACKET_LEN]);

int ipv4(int interface,
		  char buf[MAX_PACKET_LEN],
		  size_t len) {
	if (inet_addr(get_interface_ip(interface)) == ip_hdr->daddr
		&& icmp_hdr->type == ICMP_ECHO_REQUEST) {
		icmp(interface, ICMP_ECHO_REPLY, buf);

		return GOOD_PACKAGE;
	}

	// Save the checksum
	uint16_t dummy = ip_hdr->check;
	ip_hdr->check = 0;	

	// If checksum is wrong, throw the packet
	if (checksum((void *) ip_hdr, sizeof(struct iphdr)) != ntohs(dummy)) return DROP_PACKAGE;

	//Find best matching route
	struct route_table_entry *route = get_best_route(ip_hdr->daddr);

	// If route is NULL, send ICMP destination unreachable
	if (!route) {
		icmp(interface, ICMP_DEST_UNREACHABLE, buf);

		return DROP_PACKAGE;
	}

	// If TTL is less or equal to 1, send ICMP time exceeded
	if (ip_hdr->ttl <= 1) {
		icmp(interface, ICMP_TIME_EXCEEDED, buf);

		return DROP_PACKAGE;
	}

	//Update TTL and checksum
	ip_hdr->ttl--;
	ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));

	mac = get_arp_entry(route->next_hop);

	// If ARP entry is NULL, send ICMP destination unreachable
	if (!mac) {
		icmp(interface, ICMP_DEST_UNREACHABLE, buf);

		return DROP_PACKAGE;
	}

	//Update the destination MAC address
    memcpy(eth_hdr->ether_dhost, mac->mac, sizeof(mac->mac));

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	//Send the packet
	send_to_link(route->interface, buf, len);

	return GOOD_PACKAGE;
}

int arp(int interface) {

	return DROP_PACKAGE;
}

void icmp(int interface, int type,
		  char buf[MAX_PACKET_LEN]) {
	size_t len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	u_int8_t temp[6];
	memcpy(temp, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memcpy(eth_hdr->ether_shost, temp, sizeof(temp));
	eth_hdr->ether_type = htons(0x0800);

	uint32_t aux = ip_hdr->saddr; 
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;
	ip_hdr->version = 4;
	ip_hdr->ihl = 5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = htons(1);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 64;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->code = 0;
	icmp_hdr->type = type;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((void *) icmp_hdr, sizeof(struct icmphdr)));

    memcpy(eth_hdr->ether_dhost, mac->mac, sizeof(mac->mac));

	send_to_link(interface, buf, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC/ARP and route tables */
	rtable 		  	= malloc(sizeof(struct route_table_entry) * 80000);
	/* DIE is a macro for sanity checks */
	DIE(!rtable, 	"Failed to allocate memory for routing table.");

	arp_table 	  	= malloc(sizeof(struct arp_entry) * 100);
	DIE(!arp_table, "Failed to allocate memory for routing table.");
	
	/* Read the static routing table and the MAC table */
	rtable_len 	  	= read_rtable(argv[1], rtable);
	arp_table_len 	= parse_arp_table("arp_table.txt", arp_table);

receive_loop:

	int interface;
	size_t len;

	interface 		= recv_from_any_link(buf, &len);
	DIE(interface < 0, "recv_from_any_links");

	eth_hdr 		= (struct ether_header *) buf;
	ip_hdr 			= (struct iphdr *) (buf + sizeof(struct ether_header));
	icmp_hdr 		= (struct icmphdr *) (buf + sizeof(struct ether_header)
											  + sizeof(struct iphdr));

	switch (ntohs(eth_hdr->ether_type)) {
	case 0x0800:
		if (ipv4(interface, buf, len) == DROP_PACKAGE) goto receive_loop;
		break;
	case 0x0806:
		if (arp(interface) == DROP_PACKAGE) goto receive_loop;
		break;
	default:
		goto receive_loop;
	}

	goto receive_loop;

	return EXIT_FAILURE; // Should not happen
}

