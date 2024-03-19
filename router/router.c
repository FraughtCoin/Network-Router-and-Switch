#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t string_to_ipv4(char*);
struct route_table_entry* search_next_hop(struct route_table_entry*, int, uint32_t);
int compare_rtable_entry(const void*, const void*);
struct arp_entry* search_mac_by_ip(struct arp_entry*, int, uint32_t);
void print_ipv4_packet(char*);
void print_ipv4_string(uint32_t);
void print_mac_string(uint8_t*);
void print_arp_packet(char*);

// structura pentru pachetele din coada
struct waiting_packet {
	char *b;
	int len;
};

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry rtable[100000];
	int rtable_size = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), compare_rtable_entry);

	int arp_table_size = 0;
	struct arp_entry arp_table[1000]; 
	struct queue *waiting_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		int ethernet_type = ntohs(eth_hdr->ether_type);

		if (ethernet_type == 0x800) {

			struct iphdr *ip_hdr = (struct iphdr *) (buf + sizeof(struct ether_header));

			if (string_to_ipv4(get_interface_ip(interface)) == ntohl(ip_hdr->daddr)) {
				struct icmphdr *icmp_hdr = (struct icmphdr*)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));
				if (icmp_hdr->type == 8 && icmp_hdr->code == 0) {
					icmp_hdr->type = 0;
					
					icmp_hdr->checksum = 0;
					icmp_hdr->checksum = htons(checksum((uint16_t*)icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr)));

					uint32_t aux = ip_hdr->saddr;
					ip_hdr->saddr = ip_hdr->daddr;
					ip_hdr->daddr = aux;

					ip_hdr->ttl = 64;
					ip_hdr->check = 0;
					ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

					uint8_t aux2[6];
					memmove(aux2, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
					memmove(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t) * 6);
					memmove(eth_hdr->ether_dhost, aux2, sizeof(uint8_t) * 6);

					send_to_link(interface, buf, len);
				}

				continue;
			}

			uint16_t sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			uint16_t newsum = checksum((uint16_t*)ip_hdr, sizeof(struct iphdr));
			
			if (sum != newsum) {
				// bad checksum, ignore
				continue;
			}

			if (ip_hdr->ttl-- <= 1) {
				// send back icmp packet
				ip_hdr->ttl++;
				ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

				char time_exc[MAX_PACKET_LEN];

				struct ether_header *time_exc_eth_hdr = (struct ether_header*)time_exc;
				get_interface_mac(interface ,time_exc_eth_hdr->ether_shost);
				memmove(time_exc_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				time_exc_eth_hdr->ether_type = htons(0x800);
				
				struct iphdr *time_exc_ip_hdr = (struct iphdr*)(time_exc + sizeof(struct ether_header));
				time_exc_ip_hdr->version = 4;
				time_exc_ip_hdr->ihl = 5;
				time_exc_ip_hdr->tos = 0;
				time_exc_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				time_exc_ip_hdr->id = htons(1);
				time_exc_ip_hdr->frag_off = 0;
				time_exc_ip_hdr->ttl = 64;
				time_exc_ip_hdr->protocol = 1;
				time_exc_ip_hdr->saddr = ip_hdr->daddr;
				time_exc_ip_hdr->daddr = ip_hdr->saddr;
				time_exc_ip_hdr->check = 0;
				time_exc_ip_hdr->check = htons(checksum((uint16_t*)time_exc_ip_hdr, sizeof(struct iphdr)));

				struct icmphdr *time_exc_icmp_hdr = (struct icmphdr*)(time_exc + sizeof(struct ether_header) + sizeof(struct iphdr));
				time_exc_icmp_hdr->type = 11;
				time_exc_icmp_hdr->code = 0;
				time_exc_icmp_hdr->un.frag.__unused = 0;
				time_exc_icmp_hdr->un.frag.mtu = 0;
				memmove((uint8_t*)&time_exc_icmp_hdr->un.frag + 4, ip_hdr, sizeof(struct iphdr) + 8);
				time_exc_icmp_hdr->checksum = 0;
				time_exc_icmp_hdr->checksum = htons(checksum((uint16_t*)time_exc_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

				send_to_link(interface, time_exc, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				
				continue;
			}


			
			struct route_table_entry *next_hop = search_next_hop(rtable, rtable_size, ntohl(ip_hdr->daddr));
			if (next_hop == NULL) {
				// destination unreachable
				ip_hdr->ttl++;
				ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));

				char dest_unr[MAX_PACKET_LEN];
				struct ether_header *dest_unr_eth_hdr = (struct ether_header*)dest_unr;
				get_interface_mac(interface, dest_unr_eth_hdr->ether_shost);
				memmove(dest_unr_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
				dest_unr_eth_hdr->ether_type = htons(0x800);

				struct iphdr *dest_unr_ip_hdr = (struct iphdr*)(dest_unr + sizeof(struct ether_header));
				dest_unr_ip_hdr->version = 4;
				dest_unr_ip_hdr->ihl = 5;
				dest_unr_ip_hdr->tos = 0;
				dest_unr_ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);
				dest_unr_ip_hdr->id = htons(1);
				dest_unr_ip_hdr->frag_off = 0;
				dest_unr_ip_hdr->ttl = 64;
				dest_unr_ip_hdr->protocol = 1;
				dest_unr_ip_hdr->saddr = ip_hdr->daddr;
				dest_unr_ip_hdr->daddr = ip_hdr->saddr;
				dest_unr_ip_hdr->check = 0;
				dest_unr_ip_hdr->check = htons(checksum((uint16_t*)dest_unr_ip_hdr, sizeof(struct iphdr)));

				struct icmphdr *dest_unr_icmp_hdr = (struct icmphdr*)(dest_unr + sizeof(struct ether_header) + sizeof(struct iphdr));
				dest_unr_icmp_hdr->type = 3;
				dest_unr_icmp_hdr->code = 0;
				dest_unr_icmp_hdr->un.frag.__unused = 0;
				dest_unr_icmp_hdr->un.frag.mtu = 0;
				memmove((uint8_t*)&dest_unr_icmp_hdr->un.frag + 4, ip_hdr, sizeof(struct iphdr) + 8);
				dest_unr_icmp_hdr->checksum = 0;
				dest_unr_icmp_hdr->checksum = htons(checksum((uint16_t*)dest_unr_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

				send_to_link(interface, dest_unr, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8);

				continue;
			}

			struct arp_entry *next_mac = search_mac_by_ip(arp_table, arp_table_size, ntohl(next_hop->next_hop));
			if (next_mac == NULL) {
				// no next hop, arp request
				char arp_buf[MAX_PACKET_LEN];

				struct ether_header *arp_eth_header = (struct ether_header*) arp_buf;
				get_interface_mac(next_hop->interface, arp_eth_header->ether_shost);
				memset(arp_eth_header->ether_dhost, 0xff, sizeof(uint8_t) * 6);
				arp_eth_header->ether_type = htons(0x806);

				struct arp_header *arp_header = (struct arp_header*)(arp_buf + sizeof(struct ether_header));
				arp_header->htype = htons(1);
				arp_header->ptype = htons(0x800);
				arp_header->hlen = 6;
				arp_header->plen = 4;
				arp_header->op = htons(1);
				get_interface_mac(next_hop->interface, arp_header->sha);
				memset(arp_header->tha, 0x00, sizeof(uint8_t) * 6);
				arp_header->spa = htonl(string_to_ipv4(get_interface_ip(next_hop->interface)));
				arp_header->tpa = next_hop->next_hop;

				send_to_link(next_hop->interface, arp_buf, sizeof(struct ether_header) + sizeof(struct arp_header));

				struct waiting_packet *p = malloc(sizeof(struct waiting_packet));
				p->b = malloc(MAX_PACKET_LEN);
				p->len = len;
				memmove(p->b, buf, MAX_PACKET_LEN);
				queue_enq(waiting_queue, p);

				continue;
			}

			ip_hdr->check = htons(checksum((uint16_t*)ip_hdr, sizeof(struct iphdr)));
			get_interface_mac(next_hop->interface, eth_hdr->ether_shost);
			memmove(eth_hdr->ether_dhost, next_mac->mac, sizeof(uint8_t) * 6);
						
			send_to_link(next_hop->interface, buf, len);

		} else if (ethernet_type == 0x806) {
			// received arp pachet

			struct arp_header *arp_hdr = (struct arp_header*)(buf + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == 2) {
				// arp reply, adding in table

				arp_table_size++;

				arp_table[arp_table_size - 1].ip = ntohl(arp_hdr->spa);
				memmove(&arp_table[arp_table_size - 1].mac, arp_hdr->sha, sizeof(uint8_t) * 6);

				struct queue *aux = queue_create();

				while (!queue_empty(waiting_queue)) {
					struct waiting_packet *p = queue_deq(waiting_queue);
					struct ether_header *waiting_ether_hdr = (struct ether_header*)p->b;
					struct iphdr *waiting_ip_hdr = (struct iphdr*)(p->b + sizeof(struct ether_header));
					struct route_table_entry *next_hop = search_next_hop(rtable, rtable_size, ntohl(waiting_ip_hdr->daddr));
					struct arp_entry *next = search_mac_by_ip(arp_table, arp_table_size, ntohl(next_hop->next_hop));
					if (next == NULL) {
						queue_enq(aux, p);
					} else {
						waiting_ip_hdr->check = htons(checksum((uint16_t*)waiting_ip_hdr, sizeof(struct iphdr)));
						get_interface_mac(next_hop->interface, waiting_ether_hdr->ether_shost);
						memmove(waiting_ether_hdr->ether_dhost, next->mac, sizeof(uint8_t) * 6);;
						send_to_link(next_hop->interface, p->b, p->len);
						free(p->b);
						free(p);
					}
				}

				while (!queue_empty(aux)) {
					struct waiting_packet *p = queue_deq(aux);
					queue_enq(waiting_queue, p);
				}

			} else if (ntohs(arp_hdr->op) == 1) {
				// arp request, check if i am wanted
				if (ntohl(arp_hdr->tpa) == string_to_ipv4(get_interface_ip(interface))) {
					arp_hdr->op = htons(2);

					get_interface_mac(interface, eth_hdr->ether_shost);
					memmove(eth_hdr->ether_dhost, arp_hdr->sha, sizeof(uint8_t) * 6);

					memmove(arp_hdr->tha ,arp_hdr->sha, sizeof(uint8_t) * 6);
					arp_hdr->tpa = arp_hdr->spa;
					get_interface_mac(interface, arp_hdr->sha);
					arp_hdr->spa = htonl(string_to_ipv4(get_interface_ip(interface)));

					send_to_link(interface, buf, len);
				}
			}
		}
	}
}

uint32_t string_to_ipv4(char *string) {
	uint32_t r = 0xffffffff;
	char *t = strtok(string, ".");

	int m1 = atoi(t);
	t = strtok(NULL, ".");

	int m2 = atoi(t);
	t = strtok(NULL, ".");

	int m3 = atoi(t);
	t = strtok(NULL, ".");

	int m4 = atoi(t);

	return r & ((m1 << 24) | (m2 << 16) | (m3 << 8) | m4);
}

struct route_table_entry* search_next_hop(struct route_table_entry *rtable, int size, uint32_t ip_addr) {	
	int start = 0;
	int end = size - 1;
	struct route_table_entry *a = NULL;

	while (start <= end) {
		int mid = (start + end) / 2;

		if ((ip_addr & ntohl(rtable[mid].mask)) == ntohl(rtable[mid].prefix)) {
			a = rtable + mid;
			start = mid + 1;
		}
		else if ((ip_addr & ntohl(rtable[mid].mask)) < ntohl(rtable[mid].prefix)) {
			end = mid - 1;
		} else {
			start = mid + 1;
		}
	}

	return a;
}

int compare_rtable_entry(const void *a, const void *b) {
	// sorting routing table
	struct route_table_entry *e1 = (struct route_table_entry*)a;
	struct route_table_entry *e2 = (struct route_table_entry*)b;

	if (e1->mask > e2->mask) {
		return 1;
	} else if (e1->mask == e2->mask) {
		if (ntohl(e1->prefix) < ntohl(e2->prefix)) {
			return -1;
		} else {
			return 1;
		}
	}
	return -1;
}

struct arp_entry* search_mac_by_ip(struct arp_entry *arp_table, int table_size, uint32_t ip) {
	for (int i = 0; i < table_size; i++) {
		if (arp_table[i].ip == ip) {
			return arp_table + i;
		}
	}
	return NULL;
}
