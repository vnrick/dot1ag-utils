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
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <syslog.h>

#include "ieee8021ag.h"
#include "dot1ag_eth.h"

#include <pcap.h>

#define WAKEUP	20000	/* wakeup every 20 ms */

enum LOG_ACTION {
	UP,
	DOWN,
	INFO
};

typedef struct _facmap {
	char *name;
	int value;
} FACMAP;

FACMAP facilitymap[] = {
	{"LOG_KERN",	LOG_KERN,	},
	{"LOG_USER",	LOG_USER,	},
	{"LOG_MAIL",	LOG_MAIL,	},
	{"LOG_NEWS",	LOG_NEWS,	},
	{"LOG_UUCP",	LOG_UUCP,	},
	{"LOG_DAEMON",	LOG_DAEMON,	},
	{"LOG_AUTH",	LOG_AUTH,	},
	{"LOG_CRON",	LOG_CRON,	},
	{"LOG_LPR",	LOG_LPR,	},
	{"LOG_LOCAL0",	LOG_LOCAL0,	},
	{"LOG_LOCAL1",	LOG_LOCAL1,	},
	{"LOG_LOCAL2",	LOG_LOCAL2,	},
	{"LOG_LOCAL3",	LOG_LOCAL3,	},
	{"LOG_LOCAL4",	LOG_LOCAL4,	},
	{"LOG_LOCAL5",	LOG_LOCAL5,	},
	{"LOG_LOCAL6",	LOG_LOCAL6,	},
	{"LOG_LOCAL7",	LOG_LOCAL7,	},
	{NULL,		-1		}
};

pcap_t *handle;

static void
usage(void);

static int
equalstrings(char *s1, char *s2);

static void
cfm_ccm_receiver(char *ifname, struct pcap_pkthdr *pcap_hdr,
	const u_char *buf, uint16_t vlan, int verbose);

static  void
ccmlog(int mepid, enum LOG_ACTION action);

/* log status of all MEPs on HUP signal */
static void
log_mep_info(int sig) {
	ccmlog(0, INFO);
}

struct rMEP rMEPdb[MAX_MEPID + 1];
int CCMinterval = -1;
int mepid = -1;
uint8_t mdLevel = 0;
char *md = NULL;
char *ma = NULL;

int
main(int argc, char **argv) {
	int i;
	int ch;
	uint16_t vlan = 0;
	char *ifname = NULL;
	uint8_t localmac[ETHER_ADDR_LEN];
	struct bpf_program filter;  /* compiled BPF filter */
	char filter_src[1024];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct timeval tval;
	struct sigaction act;
	struct timeval now, next_ccm;
	fd_set fdset;
	int pcap_fd;
	FACMAP *m;
	char *syslog_fac = "LOG_DAEMON";
	int facility = LOG_DAEMON;
	int opts;
	int verbose = 0;

	/* schedule next CCM to be sent to now */
	gettimeofday(&next_ccm, NULL);

	/* parse command line options */
	while ((ch = getopt(argc, argv, "hi:l:m:v:t:d:a:f:V")) != -1) {
		switch(ch) {
		case 'h':
			usage();
			break;
		case 'i':
			ifname = optarg;
			break;
		case 'l':
			mdLevel = atoi(optarg);
			break;
		case 'm':
			mepid = atoi(optarg);
			break;
		case 'v':
			vlan = atoi(optarg);
			break;
		case 't':
			CCMinterval = atoi(optarg);
			break;
		case 'd':
			md = optarg;
			break;
		case 'a':
			ma = optarg;
			break;
		case 'f':
			syslog_fac = optarg;
			facility = -1;  /* will be set below if optarg OK */
			break;
		case 'V':
			verbose = 1;
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

	/* MD level should be in range 0-7 */
	if (mdLevel > 7) {
		fprintf(stderr, "MD level should be in range 0-7\n");
		exit(EXIT_FAILURE);
	}

	/* check for valid '-t' flag */
	/*
	 * 10 ms is not supported because it is probably a too short
	 * interrupt time for most Unix based systems.
	 */
	switch (CCMinterval) {
	case 100:
	case 1000:
	case 10000:
	case 60000:
	case 600000:
		break;
	default:
		fprintf(stderr, "Supported CCM interval times are:\n");
		fprintf(stderr, "100, 1000, 10000, 60000, 600000 ms\n");
		exit(EXIT_FAILURE);
	}

	/* check for mandatory '-d' flag */
	if (md == NULL) {
		usage();
	}

	/* check for mandatory '-a' flag */
	if (ma == NULL) {
		usage();
	}

	/* check for mandatory '-m' flag */
	if ((mepid < 1) || (mepid > 8191)) {
		fprintf(stderr, "MEPID should be in range 1-8191\n");
		exit(EXIT_FAILURE);
	}

	/* loop through all facility names until a correct one is found */
	for (m = facilitymap; m->name; m++) {
		if (equalstrings(syslog_fac, m->name)) {
			/* syslog_fac is a known syslog facility */
			facility = m->value;
			break;
		}
		/* try also without LOG_ prefix */
		if (equalstrings(syslog_fac, m->name + 4)) {
			/* syslog_fac is a known syslog facility */
			facility = m->value;
			break;
		}
	}

	if (facility == -1) {
		fprintf(stderr, "Syslog facility '%s' unknown, "
			"supported: LOG_KERN, LOG_USER, LOG_MAIL, "
			"LOG_NEWS, LOG_UUCP, LOG_DAEMON, LOG_AUTH, "
			"LOG_CRON, LOG_LPR, LOG_LOCAL0 .. LOG_LOCAL7\n",
			syslog_fac);
		exit(EXIT_FAILURE);
	}

	/* command line argument parsing finished */

	/* initialize remote MEP database */
	for (i = 1; i <= MAX_MEPID; i++) {
		rMEPdb[i].active = 0;
	}

	/* get Ethernet address of outgoing interface */
	if (get_local_mac(ifname, localmac) != 0) {
		perror(ifname);
		exit(EXIT_FAILURE);
	}

	openlog("dot1ag_ccd", 0, facility);

	/* define signal handler */
	act.sa_handler = &log_mep_info;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	if (sigaction(SIGHUP, &act, NULL) == -1) {
		perror("sigaction");
		exit(EXIT_FAILURE);
	}

	/* open pcap device for listening */
	handle = pcap_open_live(ifname, SNAPLEN, 1, 100, errbuf);
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
	/*
	printf("filter is %s\n", filter_src);
	*/
	pcap_compile(handle, &filter, filter_src, 0, 0);
	pcap_setfilter(handle, &filter);

	/* get pcap file descriptor */
	pcap_fd = pcap_get_selectable_fd(handle);

	/* set pcap file descriptor to non-blocking */
	opts = fcntl(pcap_fd, F_GETFL);
	if (opts < 0) {
		perror("F_GETFL on pcap fd");
		exit(EXIT_FAILURE);
	}
	opts = (opts | O_NONBLOCK);
	if (fcntl(pcap_fd, F_SETFL, opts) < 0) {
		perror("F_SETFL on pcap fd");
		exit(EXIT_FAILURE);
	}


	printf("Sending CFM frames on %s every %d %s\n", ifname,
		CCMinterval >= 1000 ? CCMinterval / 1000 : CCMinterval,
		CCMinterval >= 1000 ? "seconds" : "ms");
	printf("Listening on interface %s for CFM frames\n", ifname);

	/* listen for CFM frames */
	while (1) {
		int n;
		struct cfmhdr *cfmhdr;
		struct pcap_pkthdr *pcap_hdr;     /* header returned by pcap */
		const u_char *data;

		/* do we need to send a CCM? */
		gettimeofday(&now, NULL);
		if (cfm_timevalcmp(next_ccm, now, <)) {
			cfm_ccm_sender(ifname, vlan, mdLevel, md,
						ma, mepid, CCMinterval);
			if (CCMinterval >= 1000)  {
				next_ccm.tv_sec =
					now.tv_sec + CCMinterval / 1000;
				next_ccm.tv_usec = now.tv_usec;
			} else {
				next_ccm.tv_sec = now.tv_sec;
				next_ccm.tv_usec =
					now.tv_usec + CCMinterval * 1000;
				/* did usec counter roll over? */
				if ((now.tv_usec + CCMinterval * 1000)
								>= 1000000) {
					next_ccm.tv_sec++;
				}
			}
		}

		/* set timer to be used in select call */
		tval.tv_sec = 0;
		tval.tv_usec = WAKEUP;

		/*
		 * Wait for CFM frames.
		 */
		FD_ZERO(&fdset);
		FD_SET(pcap_fd, &fdset);
		n = select(pcap_fd + 1, &fdset, NULL, NULL, &tval);
		if (n == -1) {
			if (errno == EINTR)
				continue;
			perror("select");
			exit(EXIT_FAILURE);
		}

		/* has one of the remote MEP timers run out? */
		for (i = 1; i <= MAX_MEPID; i++) {
			if (rMEPdb[i].active == 0) {
				continue;
			}
			/* send log entry on UP to DOWN transition */
			if (cfm_timevalcmp(rMEPdb[i].rMEPwhile, now, <) &&
					(rMEPdb[i].rMEPCCMdefect == 0)) {
				ccmlog(i, DOWN);
				rMEPdb[i].rMEPCCMdefect = 1;
			}
		}
		if (n == 0)
			continue;	/* pcap_fd not ready */
		n = pcap_next_ex(handle, &pcap_hdr, &data);
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
				cfm_ccm_receiver(ifname, pcap_hdr,
					data, vlan, verbose);
				break;
			case CFM_LBM:
				break;
			case CFM_LTM:
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
	fprintf(stderr, "usage: dot1ag_ccd -i interface -t CCM-interval "
		"-d maintenance-domain -m MEPID "
		"-a maintenance-association [-v vid] [ -l mdlevel] "
		"[-f syslog-facility] [-V]\n");
	exit(EXIT_FAILURE);
}


/* return 1 if s1 and s2 are equal, return 0 otherwise; ignore case */
static int
equalstrings(char *s1, char *s2) {
	/* special case */
	if ((s1 == NULL) || (s2 == NULL)) {
		return 0;
	}
	while ((*s1 != '\0') || (*s2 != '\0')) {
		if ((*s1 == '\0') || (*s2 == '\0')) {
			/* strings not of equal length */
			return 0;
		}
		/* both s1 and s2 != 0, compare them case insensitively */
		if (tolower(*s1++) != tolower(*s2++)) {
			return 0;
		}
	}
	/* at this point both s1 and s2 are '\0', so strings are equal */
	return 1;
}



static void
cfm_ccm_receiver(char *ifname, struct pcap_pkthdr *pcap_hdr,
			const u_char *buf, uint16_t vlan, int verbose) {
	struct cfmencap *encap;
	struct cfmhdr *cfmhdr;
	struct cfm_cc *cfm_cc;
	uint8_t mdnl = 0;
	int i;
	uint8_t *md_namep;
	uint8_t sma_name_fmt;
	uint8_t smanl = 0;
	uint8_t local_mac[ETHER_ADDR_LEN];
	struct timeval now;
	int rMEPid;
	int more_tlvs;
	int tlv_length;
	uint8_t *p;

	if (get_local_mac(ifname, local_mac) != 0) {
		fprintf(stderr, "Cannot determine local MAC address\n");
		exit(EXIT_FAILURE);
	}

	encap = (struct cfmencap *) buf;

	/* discard CCM PDUs sent by us */
	if (ETHER_IS_EQUAL(encap->srcmac, local_mac)) {
		return;
	}

	/* discard if not received on our vlan */
	if ((GET_VLAN(encap) != vlan) && (IS_TAGGED((uint8_t*) encap))) {
		return;
	}
	if ((vlan != 0) && (!IS_TAGGED((uint8_t*) encap))) {
		return;
	}

	/* We need to parse the CCM header first in order to get the MEP ID */
	cfm_cc = POS_CFM_CC(buf);
	/* discard if CCM has the same MEPID as us */
	if (cfm_cc->mepid == htons(mepid)) {
		fprintf(stderr,
			"config error: CCM received with our MEPID %d "
			"(ours %d)\n",
			ntohs(cfm_cc->mepid), mepid);
		return;
	} else {
		rMEPid = ntohs(cfm_cc->mepid);
	}

	/* parse the generic CFM header */
	cfmhdr = CFMHDR(buf);

	if (verbose) {
		fprintf(stderr, "rcvd CCM: "
			"%02x:%02x:%02x:%02x:%02x:%02x, level %d",
			encap->srcmac[0], encap->srcmac[1],
			encap->srcmac[2], encap->srcmac[3],
			encap->srcmac[4], encap->srcmac[5],
			GET_MD_LEVEL(cfmhdr));
	}

	/* discard if MD Level is different from ours */
	if (GET_MD_LEVEL(cfmhdr) != mdLevel) {
		rMEPdb[rMEPid].CCMreceivedEqual = 0;
		if (verbose) {
			fprintf(stderr,
				" (expected level %d, discard frame)\n",
				mdLevel);
		}
		return;
	} else {
		rMEPdb[rMEPid].active = 1;
		rMEPdb[rMEPid].CCMreceivedEqual = 1;
	}

	/* extract the Maintenance Domain Name, if present */
	md_namep = cfm_cc->maid.var_p;

	/* create a '\0' filled buffer for MD Name */
	char mdnamebuf[DOT1AG_MAX_MD_LENGTH + 1];
	memset(mdnamebuf, '\0', sizeof(mdnamebuf));

	switch(cfm_cc->maid.format)  {
	case 0:
		/* reservered for IEEE 802.1 */
		break;
	case 1:
		/* No Maintenance Domain Name present */
		break;
	case 2:
		/* Domain Name based string */
		break;
	case 3:
		/* MAC address + 2-octet integer */
		break;
	case 4:
		/* Character string */
		mdnl = cfm_cc->maid.length;
		if ((mdnl < 1) || (mdnl > DOT1AG_MAX_MD_LENGTH)) {
			fprintf(stderr, "illegal MD Name Length: %d\n", mdnl);
			break;
		}
		/* copy MD Name to buffer, ensuring trailing '\0' */
		strncpy(mdnamebuf, (char *) md_namep, mdnl);

		if (verbose) {
			fprintf(stderr, ", MD \"%s\"", mdnamebuf);
		}
		/* discard if MD Name is different from ours */
		if (strncmp(mdnamebuf, md,
				strlen(md) > mdnl ? strlen(md) : mdnl)
				!= 0) {
			if (verbose) {
				fprintf(stderr,
					" (expected \"%s\", discard frame)\n",
					md);
			}
			return;
		}
		break;
	default:
		/*
		 *  5-31:   Reserved for IEEE 802.1
		 *  32-63:  Defined by ITU-T Y.1731
		 *  64-255: Reserved for IEEE 802.1
		 */
		 break;
	}

	/*
	 * MAID field size is 48 octets
	 * MD Name Format: 1 octet
	 * MD Name Length: 1 octet
	 * Short MA Name Format: 1 octet
	 * Short MA Name Length: 1 octet
	 * MD Name + Short MA Name <= 48 - 4
	 * Zero padding at the end
	 */

	/* extract the Short MA Name */
	/* Short MA Name Format starts after MD Name */
	sma_name_fmt = *(md_namep + mdnl);

	/* create a '\0' filled buffer, ensuring trailing '\0' */
	/* maximum SMA length is "MAID_SIZE - mdnl - 4" */
	char smanamebuf[MAID_SIZE - mdnl - 4 + 1];
	memset(smanamebuf, '\0', sizeof(smanamebuf));

	switch (sma_name_fmt) {
	case 0:
		/* Reserved for 802.1 */
		break;
	case 1:
		/* Primary VID */
		break;
	case 2:
		/* Character String */
		smanl = *(md_namep + mdnl + sizeof(sma_name_fmt));
		if (smanl < 1) {
			fprintf(stderr, "illegal Short MA Length: %d\n",
						smanl);
			break;
		}
		if (smanl + mdnl > MAID_SIZE - 4) {
			smanl = MAID_SIZE - mdnl - 4;
		}

		/* copy Short MA Name to buffer */
		strncpy(smanamebuf, (char *) (md_namep + mdnl + 2), smanl);

		if (verbose) {
			fprintf(stderr, ", MA \"%s\"", smanamebuf);
		}

		/* discard if MA name is different from ours */
		if (strncmp(smanamebuf, ma,
				strlen(ma) > smanl ? strlen(ma) : smanl)
				!= 0) {
			if (verbose) {
				fprintf(stderr,
					" (expected \"%s\", discard frame)\n",
					ma);
			}
			return;
		}
		break;
	case 3:
		/* 2-octet Integer */
		break;
	case 4:
		/* RFC2685 VPN ID */
		break;
	default:
		/*
		 *  5-31:   Reserved for IEEE 802.1
		 *  32-63:  Defined by ITU-T Y.1731
		 *  64-255: Reserved for IEEE 802.1
		 */
		 break;
	}
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		rMEPdb[rMEPid].recvdMacAddress[i] = encap->srcmac[i];
	}

	/* start parsing TLVs */
	p = POS_CFM_CC_TLVS(buf);
	more_tlvs = 1;    /* there are more TLVs to parse */
	while (more_tlvs) {
		tlv_length = ntohs(*(uint16_t *)(p + 1));
		switch (*p) {
		case TLV_END:
			/* End TLV */
			more_tlvs = 0;   /* last TLV, stop further parsing */
			break;
		case TLV_SENDER_ID:
			/* Sender ID TLV */
			/* XXX not implemented yet */
			break;
		case TLV_ORG_SPECIFIC:
			/* Organization-Specific TLV */
			/* XXX not implemented yet */
			break;
		case TLV_PORT_STATUS:
			/* Port Status TLV */
			rMEPdb[rMEPid].tlv_ps = *(p + 3);
			break;
		case TLV_INTERFACE_STATUS:
			/* Interface Status TLV */
			rMEPdb[rMEPid].tlv_is = *(p + 3);
			break;
		default:
			break;
		}
		/* skip over TLV length + value fields to next TLV */
		p += sizeof(uint16_t) + tlv_length + 1;
	}

	if (verbose) {
		fprintf(stderr, "\n");
	}

	/* send log entry on DOWN to UP transition */
	if (rMEPdb[rMEPid].rMEPCCMdefect == 1) {
		rMEPdb[rMEPid].rMEPCCMdefect = 0;
		ccmlog(rMEPid, UP);
	}

	gettimeofday(&now, NULL);

	/*
	 * Set rMEPwhile to 3.5x CCMinterval. rMEPwhile is the
	 * timeout after which it is assumed that the remote
	 * MEP is down. 3.5 times means that 3 CCM PDUs have
	 * been lost.
	 */
	switch(CCMinterval) {
	case 100:
		rMEPdb[rMEPid].rMEPwhile.tv_sec = now.tv_sec;
		rMEPdb[rMEPid].rMEPwhile.tv_usec = now.tv_usec + 350000;
		if (rMEPdb[rMEPid].rMEPwhile.tv_usec > 1000000) {
			rMEPdb[rMEPid].rMEPwhile.tv_usec--;
			rMEPdb[rMEPid].rMEPwhile.tv_sec++;
		}
		break;
	case 1000:
		rMEPdb[rMEPid].rMEPwhile.tv_sec = now.tv_sec + 3;
		rMEPdb[rMEPid].rMEPwhile.tv_usec = now.tv_usec + 500000;
		if (rMEPdb[rMEPid].rMEPwhile.tv_usec > 1000000) {
			rMEPdb[rMEPid].rMEPwhile.tv_usec--;
			rMEPdb[rMEPid].rMEPwhile.tv_sec++;
		}
		break;
	case 10000:
		rMEPdb[rMEPid].rMEPwhile.tv_sec = now.tv_sec + 35;
		rMEPdb[rMEPid].rMEPwhile.tv_usec = now.tv_usec;
		if (rMEPdb[rMEPid].rMEPwhile.tv_usec > 1000000) {
			rMEPdb[rMEPid].rMEPwhile.tv_usec--;
			rMEPdb[rMEPid].rMEPwhile.tv_sec++;
		}
		break;
	case 60000:
		rMEPdb[rMEPid].rMEPwhile.tv_sec = now.tv_sec + 210;
		rMEPdb[rMEPid].rMEPwhile.tv_usec = now.tv_usec;
		if (rMEPdb[rMEPid].rMEPwhile.tv_usec > 1000000) {
			rMEPdb[rMEPid].rMEPwhile.tv_usec--;
			rMEPdb[rMEPid].rMEPwhile.tv_sec++;
		}
		break;
	case 600000:
		rMEPdb[rMEPid].rMEPwhile.tv_sec = now.tv_sec + 2100;
		rMEPdb[rMEPid].rMEPwhile.tv_usec = now.tv_usec;
		if (rMEPdb[rMEPid].rMEPwhile.tv_usec > 1000000) {
			rMEPdb[rMEPid].rMEPwhile.tv_usec--;
			rMEPdb[rMEPid].rMEPwhile.tv_sec++;
		}
		break;
	}
}


/* map TLV Port Status value to readable string */
static char *
tlv_ps(int ps) {
	char *result;

	switch (ps) {
	case DOT1AG_PS_BLOCKED:
		result = "PsBlocked";
		break;
	case DOT1AG_PS_UP:
		result = "PsUP";
		break;
	default:
		result = "unknown";
	}
	return result;
		
}

/* map TLV Interface Status value to readable string */
static char *
tlv_is(int is) {
	char * result;

	switch (is) {
	case DOT1AG_IS_UP:
		result = "isUp";
		break;
	case DOT1AG_IS_DOWN:
		result = "isDown";
		break;
	case DOT1AG_IS_TESTING:
		result = "isTesting";
		break;
	case DOT1AG_IS_UNKNOWN:
		result = "isUnknown";
		break;
	case DOT1AG_IS_DORMANT:
		result = "isDormant";
		break;
	case DOT1AG_IS_NOTPRESENT:
		result = "isNotPresent";
		break;
	case DOT1AG_IS_LOWERLAYERDOWN:
		result = "isLowerLayerDown";
		break;
	default:
		result = "unknown";
	}
	return result;
}

/*
 * Send a log entry with the following parameters separated by commas:
 * mac-address,status,mepid,mdLevel,maintenance_domain,maintenance_association
 * e.g.:
 * 0:1a:a1:cc:d8:99,UP,37,7,domain7,test
 */
static void
ccmlog(int i, enum LOG_ACTION action) {
	int n;
	int count = 0;
	char *state;

	switch (action) {
	case UP:
		syslog(LOG_INFO, "%02x:%02x:%02x:%02x:%02x:%02x,"
			"UP,%d,%d,%s,%s,%s,%s\n",
		rMEPdb[i].recvdMacAddress[0],
		rMEPdb[i].recvdMacAddress[1],
		rMEPdb[i].recvdMacAddress[2],
		rMEPdb[i].recvdMacAddress[3],
		rMEPdb[i].recvdMacAddress[4],
		rMEPdb[i].recvdMacAddress[5],
		i, mdLevel, md, ma,
		tlv_ps(rMEPdb[i].tlv_ps),tlv_is(rMEPdb[i].tlv_is));
		break;
	case DOWN:
		syslog(LOG_CRIT, "%02x:%02x:%02x:%02x:%02x:%02x,"
			"DOWN,%d,%d,%s,%s,%s,%s\n",
		rMEPdb[i].recvdMacAddress[0],
		rMEPdb[i].recvdMacAddress[1],
		rMEPdb[i].recvdMacAddress[2],
		rMEPdb[i].recvdMacAddress[3],
		rMEPdb[i].recvdMacAddress[4],
		rMEPdb[i].recvdMacAddress[5],
		i, mdLevel, md, ma,
		tlv_ps(rMEPdb[i].tlv_ps),tlv_is(rMEPdb[i].tlv_is));
		break;
	case INFO:
		for (n = 1; n <= MAX_MEPID; n++) {
			if (rMEPdb[n].active == 0) {
				continue;
			}
			state = (rMEPdb[n].rMEPCCMdefect ? "DOWN" : "UP");
			count++;
			syslog(LOG_INFO,
				"%02x:%02x:%02x:%02x:%02x:%02x,"
				"%s,%d,%d,%s,%s,%s,%s\n",
				rMEPdb[n].recvdMacAddress[0],
				rMEPdb[n].recvdMacAddress[1],
				rMEPdb[n].recvdMacAddress[2],
				rMEPdb[n].recvdMacAddress[3],
				rMEPdb[n].recvdMacAddress[4],
				rMEPdb[n].recvdMacAddress[5],
				state, n, mdLevel, md, ma,
				tlv_ps(rMEPdb[n].tlv_ps),
				tlv_is(rMEPdb[n].tlv_is));
		}
		if (count == 0) {
			syslog(LOG_INFO, "no MEPs\n");
		}
		break;
	default:
		break;
	}
}
