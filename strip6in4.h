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
#ifndef _STRIP6IN4_H
#define _STRIP6IN4_H

#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>


#define TRUE 1
#define FALSE 0

/*Packet structure*/
struct packet{
	struct pcap_pkthdr	*h;		/*libpcap header*/
	u_char				*data;	/*Packet Data*/
	int					length;	/*Packet length*/
	void				*private; /*Private data from libpcap*/
};

/*Constant Packet structure*/
struct const_packet{
	const struct pcap_pkthdr *h;	/*libpcap header*/
	const u_char			*data;	/*Packet Data*/
	int						length;	/*Packet length*/
	void					*private; /*Private data from libpcap*/
};

/*Function to parse encapsulation*/
int do_encap(int link, const struct const_packet *old);

/*debug printf
 * Levels:
 * 	0) Always print even if debug isn't specified
 *  1) Errors and warnings... Don't overload the screen with too much output
 *  2) Notes and per-packet processing info... as verbose as needed
 */
extern int debug;
void dbgprintf(int level, const char *fmt, ...);

#endif
