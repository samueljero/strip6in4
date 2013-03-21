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


#define STRIP6IN4_VERSION 0.1
#define COPYRIGHT_YEAR 2013


pcap_t*			in;			/*libpcap input file discriptor*/
pcap_dumper_t	*out;		/*libpcap output file discriptor*/


void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
void version();
void usage();

int debug = 0;


/*Parse commandline options and open files*/
int main(int argc, char *argv[])
{
	char ebuf[200];
	char *erbuffer=ebuf;
	char *sfile=NULL;
	char *dfile=NULL;
	pcap_t* tmp;

	/*parse commandline options*/
	if(argc > 9){
		usage();
	}

	/*loop through commandline options*/
	for(int i=1; i < argc; i++){
		if(argv[i][0]!='-' || (argv[i][0]=='-' && strlen(argv[i])==1)){
			if(sfile==NULL  || argv[i][0]=='-'){
				/*assign first non-dash (or only dash) argument to the input file*/
				sfile=argv[i];
			}else{
				if(dfile==NULL){
					dfile=argv[i]; /*assign second non-dash argument to the output file*/
				}else{
					usage();
				}
			}
		}else{
			if(argv[i][1]=='V' && strlen(argv[i])==2){ /* -V */
				version();
			}else if(argv[i][1]=='h' && strlen(argv[i])==2){ /*-h*/
				usage();
			}else if(argv[i][1]=='v' && strlen(argv[i])==2){ /*-v*/
				debug++;
			}else{
				usage();
			}
		}
	}
	
	if(sfile==NULL || dfile==NULL){
		usage();
	}

	/*all options validated*/

	if(debug){
		dbgprintf(1,"Input file: %s\n", sfile);
		dbgprintf(1,"Output file: %s\n", dfile);
	}

	/*attempt to open input file*/
	in=pcap_open_offline(sfile, erbuffer);
	if(in==NULL){
		dbgprintf(0,"Error opening input file\n");
		exit(1);
	}

	/*attempt to open output file*/
	tmp=pcap_open_dead(DLT_RAW,65535);
	out=pcap_dump_open(tmp,dfile);
	if(out==NULL){
		dbgprintf(0,"Error opening output file\n");
		exit(1);
	}

	/*process packets*/
	u_char *user=(u_char*)out;
	pcap_loop(in, -1, handle_packet, user);	
	
	/*close files*/
	pcap_close(in);
	pcap_close(tmp);
	pcap_dump_close(out);
return 0;
}


/*call back function for pcap_loop--do basic packet handling*/
void handle_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	int					link_type;
	struct const_packet	old;

	/*Determine the link type for this packet*/
	link_type=pcap_datalink(in);

	/*Setup packet struct*/
	old.h=h;
	old.length=h->caplen;
	old.data=bytes;
	old.private=user;
	
	/*do all the fancy conversions*/
	if(!do_encap(link_type, &old)){
		return;
	}
return;
}

/*de-encapsulate packet*/
int decap_packet(const struct const_packet* old)
{
	struct pcap_pkthdr h;

	if(!old || !old->data || !old->h){
		dbgprintf(0,"Error: decap_packet() given bad data!\n");
		return 0;
	}

	h.ts=old->h->ts;
	h.caplen=old->length;
	h.len=old->length;

	pcap_dump((u_char*)old->private, &h, old->data);
return 0;
}

void version()
{
	dbgprintf(0, "strip6in4 version %.1f\n",STRIP6IN4_VERSION);
	dbgprintf(0, "Copyright (C) %i Samuel Jero <sj323707@ohio.edu>\n",COPYRIGHT_YEAR);
	dbgprintf(0, "This program comes with ABSOLUTELY NO WARRANTY.\n");
	dbgprintf(0, "This is free software, and you are welcome to\n");
	dbgprintf(0, "redistribute it under certain conditions.\n");
	exit(0);
}

/*Usage information for program*/
void usage()
{
	dbgprintf(0,"Usage: strip6in4 [-v] [-h] [-V] input_file output_file\n");
	dbgprintf(0, "          -v   verbose. May be repeated for additional verbosity.\n");
	dbgprintf(0, "          -V   Version information\n");
	dbgprintf(0, "          -h   Help\n");
	exit(0);
}

/*Debug Printf*/
void dbgprintf(int level, const char *fmt, ...)
{
    va_list args;
    if(debug>=level){
    	va_start(args, fmt);
    	vfprintf(stderr, fmt, args);
    	va_end(args);
    }
}
