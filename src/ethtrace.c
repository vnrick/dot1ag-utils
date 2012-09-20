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

#define INTERVAL	5   	/* listen for 5 seconds for LTRs */
#define PCAP_TIMEOUT	100	/* max number of ms to wait for packet */
#define MAX_TTL		30	/* probe until TTL 30 */

static void
usage(void);

static int next_ltm = 0;
static int got_reply = 0;
static pcap_t *handle;

static void
timeout_handler(int sig) {
	next_ltm = 1;
	pcap_breakloop(handle);   /* XXX is this needed? */
}


int
main(int argc, char **argv) {
	int ch, i;
	int n;
	char *ifname = NULL;
	uint8_t flags = 0;
	uint8_t md_level = 0;
	uint16_t vlan = 0;
	char *target;
	uint8_t ea[ETHER_ADDR_LEN];
	uint8_t sndbuf[ETHER_MAX_LEN];
	int pktsize = 0;
	int size = 0;
	uint8_t localmac[ETHER_ADDR_LEN];
	uint8_t target_mac[ETHER_ADDR_LEN];
	uint8_t LTM_mac[ETHER_ADDR_LEN];
	uint8_t ttl = 1;
	uint32_t transid;
	int hit_target = 0;
	struct pcap_pkthdr *header;     /* header returned by pcap */
	const u_char *pkt_data;
	struct bpf_program filter;  /* compiled BPF filter */
	char filter_src[1024];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct itimerval tval;
	struct sigaction act;

	/* parse command line options */
	while ((ch = getopt(argc, argv, "hi:l:v:")) != -1) {
		switch(ch) {
		case 'h':
			usage();
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			md_level = atoi(optarg);
			break;
		case 'v':
			vlan = atoi(optarg);
			break;
		case '?':
		default:
			usage();
		}
	}
	if (argc - optind != 1) {
		usage();
	}

	/* check for mandatory '-i' flag */
	if (ifname == NULL) {
		usage();
	}

	/* final command line argument is Ethernet address to ethtrace */
	target = argv[optind];
	if (eth_addr_parse(target_mac, target) != 0) {
		usage();
		exit(EXIT_FAILURE);
	}
	/* command line argument parsing finished */

	/* set LTM Group Destination MAC address */
	(void) eth_addr_parse(LTM_mac, ETHER_CFM_GROUP);
	LTM_mac[5] = 0x30 + ((md_level + 8) & 0x0F);

	/* seed random generator */
	srandom(time(0));
	/* initialize transaction ID with random value */
	transid = random();

	memset(sndbuf, 0, sizeof(sndbuf));

	if (get_local_mac(ifname, ea) < 0) {
		perror(ifname);
		exit(EXIT_FAILURE);
	}

	printf("Sending CFM LTM probe to ");
	eaprint(target_mac);
	printf("\n");
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		localmac[i] = ea[i];
	}

	/* add CFM encapsulation header to packet */
	cfm_addencap(vlan, localmac, LTM_mac, sndbuf, &size);
	pktsize += size;
	
	/* add CFM common header to packet */
	flags |= DOT1AG_LTFLAGS_USEFDBONLY;
	cfm_addhdr(md_level, flags, FIRST_TLV_LTM, CFM_LTM, sndbuf + pktsize);
	pktsize += sizeof(struct cfmhdr);

	cfm_addltm(transid, ttl, localmac, target_mac, sndbuf + pktsize);
	pktsize += sizeof(struct cfm_ltm);

	/*
	 *  finally add LTM Egress Identifier TLV
	 */

	/* XXX code below needs cleanup */
	/* Type */
	*(uint8_t *)(sndbuf + pktsize) = (uint8_t) TLV_LTM_EGRESS_IDENTIFIER;
	pktsize += sizeof(uint8_t);
	/* Egress Identifier is 8 octets */
	*(uint16_t *)(sndbuf + pktsize) = htons(8);
	pktsize += sizeof(uint16_t);
	/* add Unique Identifier (set to 0) */
	*(uint16_t *)(sndbuf + pktsize) = htons(0);
	pktsize += sizeof(uint16_t);
	/* copy MAC address to low-order 6 octets */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		*(sndbuf + pktsize + i) = localmac[i];
	}
	pktsize += ETHER_ADDR_LEN;

	/* end packet with End TLV field */
	*(uint8_t *)(sndbuf + pktsize) = htons(TLV_END);
	pktsize += sizeof(uint8_t);

	/* open pcap device for listening */
	handle = pcap_open_live(ifname, BUFSIZ, 0, PCAP_TIMEOUT, errbuf);
	if (handle == NULL) {
		perror(errbuf);
		exit(EXIT_FAILURE);
	}
	/* Compile and apply the filter */
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
	tval.it_interval.tv_sec = INTERVAL;
	tval.it_value.tv_usec = 0;
	tval.it_value.tv_sec = INTERVAL;
	if (setitimer(ITIMER_REAL, &tval, NULL) < 0) {
		perror("setitimer");
		exit(EXIT_FAILURE);
	}

	/* start while loop with sending of 1st LTM */
	next_ltm = 1;
	ttl = 0;
	got_reply = 1;
	while (1) {
		if (next_ltm) {
			if (!got_reply) {
				fprintf(stderr, "no replies for LTM %d\n",
					transid);
			}
			got_reply = 0;
			/* send next LTM with TTL + 1 */
			transid++;
			ttl++;
			if (ttl > MAX_TTL) {
				exit(EXIT_FAILURE);
			}
			cfm_ltm_setttl(ttl, sndbuf);
			cfm_ltm_settransid(transid, sndbuf);
			if (send_packet(ifname, sndbuf, pktsize) < 0) {
				fprintf(stderr, "send_packet failed\n");
				exit(EXIT_FAILURE);
			}
			printf("ttl %d: LTM with id %d\n", ttl, transid);
			next_ltm = 0;
		}

		n = pcap_next_ex(handle, &header, &pkt_data);
		switch (n) {
		case -1:
			break;
		case 0:
			break;
		case 1:
			if (cfm_matchltr((uint8_t *) pkt_data, localmac, vlan,
				md_level, transid, &hit_target)) {
					print_ltr((uint8_t *) pkt_data);
					got_reply = 1;
			}
			if (hit_target) {
				exit(EXIT_SUCCESS);
			}
			break;
		default:
			break;
		}
	}
	return 0;
}


static void
usage() {
	fprintf(stderr, "usage: ethtrace -i interface [-v vlan] [-l mdlevel] "
				"address\n");
	exit(EXIT_FAILURE);
}
