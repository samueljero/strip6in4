/******************************************************************************
Utility to create a pcap file of a 6in4 stream present in an origin pcap file

Copyright (C) 2013  Samuel Jero <sj323707@ohio.edu>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Author: Samuel Jero <sj323707@ohio.edu>
Date: 03/2013
******************************************************************************/
#include "strip6in4.h"
#include "encap.h"
#include <pcap/sll.h>
#include <pcap/vlan.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>

/*Encapsulation start point and link layer selector*/
int do_encap(int link, const struct const_packet *old)
{
	switch(link){
		case DLT_EN10MB:
				/*Ethernet*/
				if(!ethernet_encap(old)){
						return 0;
				}
				break;
		case DLT_RAW:
				/*Raw. Just IP*/
				if(!ipv4_encap(old)){
						return 0;
				}
				break;
		case DLT_LINUX_SLL:
				/*Linux Cooked Capture*/
				if(!linux_cooked_encap(old)){
					return 0;
				}
				break;
		default:
				dbgprintf(0, "Unknown Link Layer\n");
				return 0;
	}
return 1;
}

/*Standard Ethernet Encapsulation*/
int ethernet_encap(const struct const_packet *old)
{
		struct ether_header	*ethh;
		struct const_packet nold;

		/*Safety checks*/
		if(!old|| !old->data ||!old->h){
			dbgprintf(0,"Error: Ethernet Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct ether_header)){
			dbgprintf(0, "Error: Ethernet Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Cast Pointer*/
		ethh=(struct ether_header*)(old->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data+ sizeof(struct ether_header);
		nold.length= old->length - sizeof(struct ether_header);
		nold.h=old->h;
		nold.private=old->private;

		/*Select Next Protocol*/
		switch(ntohs(ethh->ether_type)){
			case ETHERTYPE_IP:
					if(!ipv4_encap(&nold)){
							return 0;
					}
					break;
			case ETHERTYPE_IPV6:
					if(!ipv6_encap(&nold)){
							return 0;
					}
					break;
			case ETHERTYPE_VLAN:
					if(!ethernet_vlan_encap(&nold)){
							return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at Ethernet\n");
					return 0;
					break;
		}
return 1;
}

/*Ethernet 802.1Q VLAN Encapsulation*/
int ethernet_vlan_encap(const struct const_packet *old)
{
		struct vlan_tag		*tag;
		struct const_packet nold;

		/*Safety checks*/
		if(!old || !old->data || !old->h){
			dbgprintf(0,"Error: Ethernet VLAN Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct vlan_tag)){
			dbgprintf(0, "Error: Ethernet VLAN Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Cast Pointer*/
		tag=(struct vlan_tag*)(old->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data+ sizeof(struct vlan_tag);
		nold.length= old->length - sizeof(struct vlan_tag);
		nold.h=old->h;
		nold.private=old->private;

		/*Select Next Protocol*/
		switch(ntohs(tag->vlan_tci)){
			case ETHERTYPE_IP:
					if(!ipv4_encap(&nold)){
							return 0;
					}
					break;
			case ETHERTYPE_IPV6:
					if(!ipv6_encap(&nold)){
							return 0;
					}
					break;
			case ETHERTYPE_VLAN:
					if(!ethernet_vlan_encap(&nold)){
							return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at Ethernet VLAN tag\n");
					return 0;
					break;
		}
return 1;
}

/*IPv6 Encapsulation*/
int ipv6_encap(const struct const_packet *old)
{
		struct ip6_hdr 		*iph;
		struct const_packet	nold;

		/*Safety checks*/
		if(!old->data || !old->h){
			dbgprintf(0,"Error: IPv6 Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct ip6_hdr)){
			dbgprintf(0, "Error: IPv6 Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Cast Pointer*/
		iph=(struct ip6_hdr*)(old->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data + sizeof(struct ip6_hdr);
		nold.length= old->length - sizeof(struct ip6_hdr);
		nold.h=old->h;
		nold.private=old->private;

		/*Confirm that this is IPv6*/
		if((ntohl(iph->ip6_ctlun.ip6_un1.ip6_un1_flow) & (0xF0000000)) == (60000000)){
			dbgprintf(1, "Note: Packet is not IPv6\n");
			return 0;
		}

		/*Select Next Protocol*/
		switch(iph->ip6_ctlun.ip6_un1.ip6_un1_nxt){
			case 41:
					/*6in4*/
					if(!decap_packet(&nold)){
						return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at IPv6\n");
					return 0;
					break;
		}
return 1;
}

/*IPv4 Encapsulation*/
int ipv4_encap(const struct const_packet *old)
{
		struct iphdr 		*iph;
		struct const_packet	nold;

		/*Safety checks*/
		if(!old || !old->data || !old->h){
			dbgprintf(0,"Error: IPv4 Encapsulation Function given bad data!\n");
			return 0;
		}
		if(old->length < sizeof(struct iphdr)){
			dbgprintf(0, "Error: IPv4 Encapsulation Function given packet of wrong size!\n");
			return 0;
		}

		/*Cast Pointer*/
		iph=(struct iphdr*)(old->data);

		/*Adjust pointers and lengths*/
		nold.data= old->data +iph->ihl*4;
		nold.length= old->length -iph->ihl*4;
		nold.h=old->h;
		nold.private=old->private;

		/*Confirm that this is IPv4*/
		if(iph->version!=4){
			dbgprintf(1, "Note: Packet is not IPv4\n");
			return 0;
		}

		/*Select Next Protocol*/
		switch(iph->protocol){
			case 41:
					/*6in4*/
					if(!decap_packet(&nold)){
						return 0;
					}
					break;
			default:
					dbgprintf(1, "Unknown Next Protocol at IPv4\n");
					return 0;
					break;
		}
return 1;
}

int linux_cooked_encap(const struct const_packet *old)
{
	struct sll_header		*slh;
	struct const_packet		nold;


	/*Safety checks*/
	if(!old ||  !old->data ||!old->h){
		dbgprintf(0,"Error: SLL Encapsulation Function given bad data!\n");
		return 0;
	}
	if(old->length < sizeof(struct sll_header)){
		dbgprintf(0, "Error: SLL Encapsulation Function given packet of wrong size!\n");
		return 0;
	}

	/*Cast Pointer*/
	slh=(struct sll_header*)(old->data);

	/*Adjust pointers and lengths*/
	nold.data= old->data + sizeof(struct sll_header);
	nold.length= old->length - sizeof(struct sll_header);
	nold.h=old->h;
	nold.private=old->private;

	/*Confirm that this is SLL*/
	if(ntohs(slh->sll_pkttype) > 4){
		dbgprintf(1, "Note: Packet is not SLL (Linux Cooked Capture)\n");
		return 0;
	}

	/*Select Next Protocol*/
	switch(ntohs(slh->sll_protocol)){
		case ETHERTYPE_IP:
				if(!ipv4_encap(&nold)){
						return 0;
				}
				break;
		case ETHERTYPE_IPV6:
				if(!ipv6_encap(&nold)){
						return 0;
				}
				break;
		default:
				dbgprintf(1, "Unknown Next Protocol at SLL\n");
				return 0;
				break;
	}
return 1;
}
