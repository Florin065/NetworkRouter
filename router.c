#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_DEST_UNREACHABLE 3
#define ICMP_TIME_EXCEEDED 11

#define DROP_PACKAGE -1
#define GOOD_PACKAGE  0

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* ARP table */
struct arp_entry *arp_table;
int arp_table_len;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;

	for (size_t i = 0; i < rtable_len; i++) {
		if ((rtable[i].mask & ip_dest) == (rtable[i].prefix & rtable[i].mask)) {
			if (best_route == NULL) best_route = &rtable[i];
			else if (best_route->mask < rtable[i].mask) best_route = &rtable[i];
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
		  struct ether_header *eth_hdr,
		  char buf[MAX_PACKET_LEN],
		  size_t len,
		  struct iphdr *ip_hdr);

int ipv4(int interface,
		  struct ether_header *eth_hdr,
		  char buf[MAX_PACKET_LEN],
		  size_t len,
		  struct iphdr *ip_hdr) {

	// Save the checksum
	uint16_t dummy = ip_hdr->check;
	ip_hdr->check = 0;	

	// If checksum is wrong, throw the packet
	if (checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)) != ntohs(dummy)) return DROP_PACKAGE;

	printf("Checksum is good\n");

	//Find best matching route
	struct route_table_entry *route = get_best_route(ip_hdr->daddr);

	// If route is NULL, send ICMP destination unreachable
	if (!route) {
		icmp(interface, ICMP_DEST_UNREACHABLE, eth_hdr, buf, len, ip_hdr);

		return DROP_PACKAGE;
	}

	// If TTL is less or equal to 1, send ICMP time exceeded
	if (ntohs(ip_hdr->ttl) <= 1) {
		icmp(interface, ICMP_TIME_EXCEEDED, eth_hdr, buf, len, ip_hdr);

		return DROP_PACKAGE;
	}

	//Update TTL and checksum
	ip_hdr->ttl--;
	ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(struct iphdr)));

	struct arp_entry *arp = get_arp_entry(route->next_hop);

	// If ARP entry is NULL, send ICMP destination unreachable
	if (!arp) {
		icmp(interface, ICMP_DEST_UNREACHABLE, eth_hdr, buf, len, ip_hdr);

		return DROP_PACKAGE;
	}

	//Update the destination MAC address
    memcpy(eth_hdr->ether_dhost, arp->mac, sizeof(arp->mac));

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	//Send the packet
	send_to_link(route->interface, buf, len);

	return GOOD_PACKAGE;
}

int arp(int interface, struct ether_header *eth_hdr) {
	return DROP_PACKAGE;
}

void icmp(int interface, int type,
		  struct ether_header *eth_hdr,
		  char buf[MAX_PACKET_LEN],
		  size_t len,
		  struct iphdr *ip_hdr) {

	
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	/* Code to allocate the MAC and route tables */
	rtable 		  = malloc(sizeof(struct route_table_entry) * 100000);
	/* DIE is a macro for sanity checks */
	DIE(rtable == NULL, "memory");

	arp_table 	  = malloc(sizeof(struct arp_entry) * 100);
	DIE(arp_table == NULL, "memory");
	
	/* Read the static routing table and the MAC table */
	rtable_len 	  = read_rtable(argv[1], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

receive_loop:

	int interface;
	size_t len;

	interface = recv_from_any_link(buf, &len);
	DIE(interface < 0, "recv_from_any_links");
	printf("We have received a packet\n");

	struct ether_header *eth_hdr = (struct ether_header *) buf;
	struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

	switch (ntohs(eth_hdr->ether_type)) {
	case 0x0800:
		if (ipv4(interface, eth_hdr, buf, len, ip_hdr) == DROP_PACKAGE) goto receive_loop;
		break;
	case 0x0806:
		if (arp(interface, eth_hdr) == DROP_PACKAGE) goto receive_loop;
		break;
	default:
		goto receive_loop;
	}

	goto receive_loop;

	return EXIT_FAILURE; // Should not happen
}

