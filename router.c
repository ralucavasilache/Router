#include "queue.h"
#include "skel.h"
#include <sys/stat.h> 
#include <fcntl.h>
#include <string.h>

#define MAX_DIM_RT 65000
#define MAX_DIM_ARPT 6

struct rtable_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	uint32_t interface;
};

struct arp_table_entry {
	uint32_t ip;
	uint8_t mac[ETH_ALEN];
};

/* parseaza tabela de rutare si o memoreaza intr-un vector cu
   elemente de tip rtable_entry;
   intoarce dimensiunea vectorului */
int parse_routing_table(char* file, struct rtable_entry* rtable) {

	char buf[100];
	char *prefix_aux;
	char *next_hop_aux;
	char *mask_aux;
	char *interface_aux;
	int rt_size = 0;

	FILE *f = fopen(file, "r");
	if (f == NULL) {
		perror("Cannot open file!\n");
		return -1;
	}
	
	while (fgets(buf, sizeof(buf), f) != NULL) {
		
		prefix_aux = strtok(buf, " ");
		next_hop_aux = strtok(NULL, " ");
		mask_aux = strtok(NULL, " ");
		interface_aux = strtok(NULL, " \n");

		rtable[rt_size].prefix = inet_addr(prefix_aux);
		rtable[rt_size].next_hop = inet_addr(next_hop_aux);
		rtable[rt_size].mask = inet_addr(mask_aux);
		rtable[rt_size].interface = atoi(interface_aux);

		rt_size++;
	}

	fclose(f);
	return rt_size;
}
/* comparator folosit pentru sortarea tabelei de rutare crescator
   dupa prefix si descrescator dupa masca */
int comparator(const void *entry1, const void *entry2)
{
	if (((struct rtable_entry *)entry1)->prefix != ((struct rtable_entry *)entry2)->prefix) {
		return (((struct rtable_entry *)entry1)->prefix - ((struct rtable_entry *)entry2)->prefix);
	} else {
		return (((struct rtable_entry *)entry2)->mask - ((struct rtable_entry *)entry1)->mask);
	}
}
/* gaseste cea mai buna ruta, folosind cautare binara */
struct rtable_entry* get_best_route(struct rtable_entry *rtable, int start, int end, uint32_t ip) {
	end--;

	while(start <= end) {
		int middle = start + (end - start)/2;

		if((ip & rtable[middle].mask) == rtable[middle].prefix) {
			return &rtable[middle];
		}

		if((ip & rtable[middle].mask) > rtable[middle].prefix) {
			start = middle + 1;
		} else {
			end = middle - 1;
		}
	}
	return NULL;
}

/* returneaza adresa mac corespunzatoare ip-ului trimis ca parametru */
struct arp_table_entry *get_mac_from_arp(struct arp_table_entry *arp_table, int arp_size, uint32_t ip) {
	
	for (int i = 0; i < arp_size; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}

	return NULL;
}

int main(int argc, char *argv[])
{

	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;
	init(argc - 2, argv + 2);

	/* parsare + sortare tabela de rutare */
	struct rtable_entry *rtable = malloc(sizeof(struct rtable_entry) * MAX_DIM_RT);
	int rt_size = parse_routing_table(argv[1], rtable);
	qsort(rtable, rt_size, sizeof(struct rtable_entry), comparator);

	/* initializare tabela arp */
	struct arp_table_entry *arp_table = malloc(sizeof(struct arp_table_entry) * MAX_DIM_ARPT);
	int arpt_size = 0;

	/* coada unde se retin pachetele carora nu li se cunoaste adresa mac */
	queue awaiting = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		struct ether_header *eth_hdr = (struct ether_header *)m.payload;

		/* daca este un pachet IP*/
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {

			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			/* daca este un pachet destinat mie */
			if (inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
				struct icmphdr *icmp = parse_icmp(m.payload);
				/* raspund doar daca este un pachet de tip ICMP_ECHO,
					cu un pachet ICMP_ECHOREPLY */
				if ((icmp != NULL) && (icmp->type == ICMP_ECHO)) {
					
					send_icmp(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
							eth_hdr->ether_dhost, eth_hdr->ether_shost,
							0, 0, m.interface, icmp->un.echo.id,
							icmp->un.echo.sequence);
				}
				continue;
			}

			/* daca are ttl <=1  -> arunca pachetul, trimite time exceeded*/
			if(ip_hdr->ttl <= 1) {

				send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
								eth_hdr->ether_dhost, eth_hdr->ether_shost,
								ICMP_TIME_EXCEEDED, 0, m.interface);
				continue;
			}

			/* daca checksum este gresit, arunca pachetul */
			if(ip_checksum(ip_hdr, sizeof(struct iphdr))) {
				continue;
			}

			/* decrementez ttl */
			ip_hdr->ttl--;
			/* recalculeaza checksum */
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));


			/* caut best route */
			struct rtable_entry* best_entry = get_best_route(rtable, 0, rt_size, ip_hdr->daddr);
			/* daca nu gasesc nicio ruta -> dest_unreachable */
			if (best_entry == NULL) {
				send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)),
									eth_hdr->ether_dhost, eth_hdr->ether_shost,
									ICMP_DEST_UNREACH, 0, m.interface);
				continue;
			/* daca am gasit o ruta -> caut adresa mac pt next hop in arp_table */
			} else {
				struct arp_table_entry *arp_entry = get_mac_from_arp(arp_table, arpt_size, ((*best_entry).next_hop));
				
				/* se modifica interfata si adresa mac a sursei */
				get_interface_mac(best_entry->interface, eth_hdr->ether_shost);
				m.interface = best_entry->interface;

				/* daca mac-ul exista deja in tabela arp -> trimitem pachetul mai departe */
				if (arp_entry != NULL) {

					memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(arp_entry->mac));
					send_packet(best_entry->interface, &m);
				
				/* daca nu exista in tabela arp, pun pachetul in coada si trimit ARP_REQ*/
				} else {

					packet *copy = malloc (sizeof (packet) * 1);
					memcpy(copy, &m, sizeof(m));
					
					queue_enq(awaiting, copy);
					/* trimite ARP_REQ*/

					/* adresa de broadcast - > adresa mac destinatie */
					uint8_t broadcast_addr[6];
					int convert = hwaddr_aton("ff:ff:ff:ff:ff:ff", broadcast_addr);
					if(convert == -1) {
						printf("adress not a mac\n");
					}
					/* adresa mea mac - > adresa mac sursa */
					uint8_t my_mac[ETH_ALEN];
					get_interface_mac(best_entry->interface, my_mac);

					struct ether_header *new_eth = malloc(sizeof(struct ether_header) * 1);
					build_ethhdr(new_eth, my_mac, broadcast_addr, htons(ETHERTYPE_ARP));
					send_arp(((*best_entry).next_hop), inet_addr(get_interface_ip(best_entry->interface)),
					         new_eth, best_entry->interface, htons(ARPOP_REQUEST));
				}

				continue;
			}
		}
		/* daca este un pachet ARP*/
		if (parse_arp(m.payload) != NULL) {

			struct arp_header *arp_hdr = parse_arp(m.payload);

				/* daca este un pachet arp request destinat mie, raspundcu arp reply */
				if ((ntohs(arp_hdr->op) == ARPOP_REQUEST)) {
					
					if (arp_hdr->tpa == inet_addr(get_interface_ip(m.interface))) {

						struct ether_header *new_eth = malloc(sizeof(struct ether_header) * 1);
						uint8_t my_mac[ETH_ALEN];

						get_interface_mac(m.interface, my_mac);
						build_ethhdr(new_eth, my_mac, arp_hdr->sha, 1544);

						send_arp(arp_hdr->spa, arp_hdr->tpa, new_eth, m.interface, htons(ARPOP_REPLY));
						continue;
					}
				/* daca este un arp reply */
				} else if (ntohs(arp_hdr->op) == ARPOP_REPLY) {

					/* daca coada este goala -> primesc reply fara sa fi facut request si nu trebuie sa fac nimic */
					if (!queue_empty(awaiting)) {
						
						/* altfel, updatez tabela de rutare */
						arp_table[arpt_size].ip = arp_hdr->spa;
						memcpy(arp_table[arpt_size].mac, arp_hdr->sha, sizeof(arp_hdr->sha));
						arpt_size++;

						/* scot pachetul din coada */
						packet *pkg = (packet*)queue_deq(awaiting);
						struct ether_header *eth_hdr1 = (struct ether_header *)((*pkg).payload);
						
						/* trimit pachetu; */
						memcpy(eth_hdr1->ether_dhost, arp_hdr->sha, sizeof(arp_hdr->sha));
						send_packet(((*pkg).interface), pkg);
						continue;
					}
				}

			continue;
		}
	}
}
