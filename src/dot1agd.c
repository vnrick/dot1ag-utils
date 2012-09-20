/*
 * Copyright (c) 2011
 * Author: Ronald van der Pol
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/socket.h>

#include "ieee8021ag.h"
#include "dot1ag_eth.h"

#include <pcap.h>

#define INTERVAL	1

pcap_t *handle;

static void usage(void);

static void
timeout_handler(int sig) {
	pcap_breakloop(handle);   /* XXX is this needed? */
}


int
main(int argc, char **argv) {
	int ch;
	char *ifname = NULL;
	uint8_t localmac[ETHER_ADDR_LEN];
	struct bpf_program filter;  /* compiled BPF filter */
	char filter_src[1024];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct itimerval tval;
	struct sigaction act;

	/* parse command line options */
	while ((ch = getopt(argc, argv, "hi:l:v:c:")) != -1) {
		switch(ch) {
		case 'h':
			usage();
			break;
		case 'i':
			ifname = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}
	if (argc - optind != 0) {
		usage();
	}

	/* check for mandatory '-i' flag */
	if (ifname == NULL) {
		usage();
	}
	/* command line argument parsing finished */

	/* get Ethernet address of outgoing interface */
	if (get_local_mac(ifname, localmac) != 0) {
		perror(ifname);
		exit(EXIT_FAILURE);
	}

	/* open pcap device for listening */
	handle = pcap_open_live(ifname, BUFSIZ, 1, 100, errbuf);
	if (handle == NULL) {
		perror(errbuf);
		exit(EXIT_FAILURE);
	}

	/* Compile and apply the filter */

	/*
	 * Filter to receive CFM frames (Ethertype 0x8902) only.
	 * Filter on both untagged (ether[12:2]) or 802.1Q tagged
	 * (ether[16:2]) frames.
	 */
	sprintf(filter_src, "ether[12:2] == 0x%x or "
		"(ether[12:2] == 0x%x and ether[16:2] == 0x%x)",
		ETYPE_CFM, ETYPE_8021Q, ETYPE_CFM);
	pcap_compile(handle, &filter, filter_src, 0, 0);
	pcap_setfilter(handle, &filter);

	 /* define signal handler */
	act.sa_handler = &timeout_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGALRM, &act, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	/* set timer to INTERVAL seconds */
	tval.it_interval.tv_usec = 0;
	tval.it_interval.tv_sec = 1;
	tval.it_value.tv_usec = 0;
	tval.it_value.tv_sec = 1;
	if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
		perror("setitimer");
		exit(EXIT_FAILURE);
	}

	printf("Listening on interface %s for CFM frames\n", ifname);

	/* listen for CFM frames */
	while (1) {
		int n;
		struct cfmhdr *cfmhdr;
		struct pcap_pkthdr *header;     /* header returned by pcap */
		const u_char *data;

		/*
		 * Wait for a CFM frames.
		 */
		n = pcap_next_ex(handle, &header, &data);
		switch (n) {
		case -1:
			pcap_perror(handle, "pcap_next_ex");
			break;
		case 0:
			break;
		case 1:
			cfmhdr = CFMHDR(data);
			switch (cfmhdr->opcode) {
			case CFM_CCM:
				break;
			case CFM_LBM:
				cfm_send_lbr(ifname, (uint8_t *) data,
						(int) header->caplen);
				break;
			case CFM_LTM:
				/* Linktrace Responder */
				processLTM(ifname, (uint8_t *) data);
				break;
			default:
				break;
			}
			break;
		default:
			break;
		}
	}

	exit(EXIT_SUCCESS);
}

static void
usage() {
	fprintf(stderr, "usage: dot1agd -i interface\n");
	exit(EXIT_FAILURE);
}
