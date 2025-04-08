#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RTABLE_MAX_SIZE 		80000
#define ARP_TABLE_MAX_SIZE 		100

#define ICMP_ECHO_REPLY 		0
#define ICMP_DEST_UNREACHABLE 	3
#define ICMP_ECHO_REQUEST 		8
#define ICMP_TIME_EXCEEDED 		11

#define ARP_OP_REQUEST 			1
#define ARP_OP_REPLY 			2

#define DROP_PACKAGE 			-1
#define GOOD_PACKAGE  			0

#define ZERO					0
#define ONE						1
#define TWO						2
#define FOUR					4
#define FIVE					5
#define SIX						6
#define SIXTYFOUR				64

#define IPV4 					0x0800
#define ARP 					0x0806

/* Routing table */
struct route_table_entry *rtable;
size_t rtable_len;

/* ARP table */
struct arp_entry *arp_table;
size_t arp_table_len;

/* MAC address */
struct arp_entry *mac;

/* Headers */
struct ether_header *eth_hdr;
struct iphdr *ip_hdr;
struct arp_header *arp_hdr;
struct icmphdr *icmp_hdr;

struct route_table_entry *route;

/* Queue */
queue q;

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	struct route_table_entry *best_route = NULL;
	size_t i = ZERO;

check_route:
	if (i >= rtable_len) {
		goto end;
	}

	if ((rtable[i].mask & ip_dest) == (rtable[i].prefix & rtable[i].mask)) {
		if (!best_route) {
			best_route = &rtable[i];
		} else if (best_route->mask < rtable[i].mask) {
			best_route = &rtable[i];
		}
	}

	i++;
	goto check_route;

end:
	return best_route; 
}

struct arp_entry *get_arp_entry(uint32_t ip_dest) {
    size_t i = ZERO;
loop_start:
    if (i < arp_table_len) {
        if (arp_table[i].ip == ip_dest) {
            return &arp_table[i];
        }
        i++;
        goto loop_start;
    }
    return NULL;
}

void icmp(int interface, int type, char buf[MAX_PACKET_LEN]);
void arp_req();

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
	ip_hdr->check = ZERO;	

	// If checksum is wrong, throw the packet
	if (checksum((void *) ip_hdr, sizeof(struct iphdr)) != ntohs(dummy)) return DROP_PACKAGE;

	// If route is NULL, send ICMP destination unreachable
	if (!route) {
		icmp(interface, ICMP_DEST_UNREACHABLE, buf);

		return DROP_PACKAGE;
	}

	// If TTL is less or equal to 1, send ICMP time exceeded
	if (ip_hdr->ttl <= ONE) {
		icmp(interface, ICMP_TIME_EXCEEDED, buf);

		return DROP_PACKAGE;
	}

	//Update TTL and checksum
	ip_hdr->ttl--;
	ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));

	//Find MAC address of next hop
	mac = get_arp_entry(route->next_hop);

	// If MAC is NULL, send ARP request
	if (!mac) {
		arp_req();

		return DROP_PACKAGE;
	}

	//Update the destination MAC address
    memcpy(eth_hdr->ether_dhost,
		   mac->mac,
		   sizeof(mac->mac));

	//Update the source MAC address, by getting the address of the 
	//best route interface;
	get_interface_mac(route->interface, eth_hdr->ether_shost);

	//Send the packet
	send_to_link(route->interface, buf, len);

	return GOOD_PACKAGE;
}

void arp_req() {
	// Create the packet
	char buf[MAX_PACKET_LEN];
	memset(buf, ZERO, MAX_PACKET_LEN);

	// Set the headers
	struct ether_header *ethh = (struct ether_header *)  buf;
	struct arp_header *arph = (struct arp_header *) (ethh + sizeof(struct ether_header));

	// Set the length
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);

	
	// Set the destination MAC address to broadcast
	uint8_t *dest = calloc(SIX, sizeof(uint8_t));
	memset(dest, 0xFF, SIX * sizeof(uint8_t));

	memmove(ethh->ether_dhost, dest, SIX * sizeof(uint8_t));

	// Set the source MAC address to the interface MAC address
	get_interface_mac(route->interface, ethh->ether_shost);

	// Set the type to ARP
	ethh->ether_type = htons(ARP);

	// Set the hardware type to Ethernet
	arph->htype = ONE;

	// Set the protocol type to IPv4
	arph->ptype = htons(IPV4);

	// Set the hardware address length to 6
	arph->hlen = SIX;

	// Set the protocol address length to 4
	arph->plen = FOUR;

	// Set the operation to ARP request
	arph->op = htons(ARP_OP_REQUEST);

	// Set the sender MAC address to the interface MAC address
	get_interface_mac(route->interface, arph->sha);

	// Set the sender IP address to the interface IP address
	arph->spa = inet_addr(get_interface_ip(route->interface));

	memmove(arph->tha, dest, SIX * sizeof(uint8_t));

	// Set the target IP address to the destination IP address
	arph->tpa = route->next_hop;

	// Copy the headers to the packet
	memmove(buf, ethh, sizeof(struct ether_header));
	memmove(buf + sizeof(struct ether_header), arph, sizeof(struct arp_header));

	// Send the packet
	send_to_link(route->interface, buf, len);
}

int arp(int interface, char buf[MAX_PACKET_LEN], size_t len) {
	if (ntohs(arp_hdr->op) == ARP_OP_REQUEST) {
		arp_hdr->op = htons(ARP_OP_REPLY);

		memmove(arp_hdr->tha, arp_hdr->sha, sizeof(arp_hdr->sha));

		uint8_t temp[SIX * sizeof(uint8_t)];
		get_interface_mac(interface, temp);
		memmove(arp_hdr->sha, temp, sizeof(arp_hdr->sha));

		arp_hdr->tpa = arp_hdr->spa;
		arp_hdr->spa = inet_addr(get_interface_ip(interface));

		memmove(eth_hdr->ether_dhost, arp_hdr->tha, SIX * sizeof(uint8_t));
		get_interface_mac(interface, eth_hdr->ether_shost);

		send_to_link(interface, buf, len);
	}
	else if (ntohs(arp_hdr->op == ARP_OP_REPLY)) return DROP_PACKAGE;

	return DROP_PACKAGE;
}

void icmp(int interface, int type,
	char buf[MAX_PACKET_LEN]) {
	size_t len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

	u_int8_t temp[SIX * sizeof(uint8_t)];
	memmove(temp, eth_hdr->ether_dhost, sizeof(eth_hdr->ether_dhost));
	memmove(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(eth_hdr->ether_shost));
	memmove(eth_hdr->ether_shost, temp, sizeof(temp));
	eth_hdr->ether_type = htons(IPV4);

	uint32_t aux = ip_hdr->saddr; 
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;
	ip_hdr->version = FOUR;
	ip_hdr->ihl = FIVE;
	ip_hdr->tos = ZERO;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->id = ONE;
	ip_hdr->frag_off = ZERO;
	ip_hdr->ttl = SIXTYFOUR;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->check = ZERO;
	ip_hdr->check = htons(checksum((void *) ip_hdr, sizeof(struct iphdr)));

	icmp_hdr->code = ZERO;
	icmp_hdr->type = type;
	icmp_hdr->checksum = ZERO;
	icmp_hdr->checksum = htons(checksum((void *) icmp_hdr, sizeof(struct icmphdr)));

    memmove(eth_hdr->ether_dhost, mac->mac, sizeof(mac->mac));

	send_to_link(interface, buf, len);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - TWO, argv + TWO);

	/* Code to allocate the MAC/ARP and route tables */
	rtable = calloc(RTABLE_MAX_SIZE, sizeof(struct route_table_entry));
	/* DIE is a macro for sanity checks */
	DIE(!rtable, "Failed to allocate memory for routing table.");

	arp_table = calloc(ARP_TABLE_MAX_SIZE, sizeof(struct arp_entry));
	DIE(!arp_table, "Failed to allocate memory for routing table.");
	
	/* Read the static routing table and the MAC table */
	rtable_len = read_rtable(argv[ONE], rtable);
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);

	q = queue_create();

receive_loop:

	int interface;
	size_t len;

	interface = recv_from_any_link(buf, &len);
	DIE(interface < ZERO, "recv_from_any_links");

	eth_hdr = (struct ether_header *)  buf;
	ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));
	icmp_hdr = (struct icmphdr *) (buf + sizeof(struct ether_header) + sizeof(struct iphdr));
	arp_hdr = (struct arp_header *) (buf + sizeof(struct ether_header));

	//Find best matching route
	route = get_best_route(ip_hdr->daddr);

	switch (ntohs(eth_hdr->ether_type)) {
	case IPV4:
		if (ipv4(interface, buf, len) == DROP_PACKAGE) goto receive_loop;
		break;
	case ARP:
		 goto receive_loop;
		break;
	default:
		goto receive_loop;
	}

	goto receive_loop;

	return EXIT_FAILURE; // Should not happen
}

