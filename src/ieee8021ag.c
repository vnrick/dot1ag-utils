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

/*
 * Packet encoding taken from:
 * http://standards.ieee.org/getieee802/download/802.1ag-2007.pdf
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ieee8021ag.h"

/* Parse a MAC address */
int 
eth_addr_parse(uint8_t *addr, char *str) {
	unsigned int cval;
	char c, orig, sep;
	int pos;

	cval = 0;
	sep  = 0;
	pos  = 0;

	memset(addr, 0, ETHER_ADDR_LEN);

	do {
		c = orig = *str++;

		if (c == 0) {
			if (!sep) return (-1);
			c = sep;
		}

		switch(c) {
			case '0' ... '9':
				cval = (cval << 4) + (c - '0');
				break;
			case 'a' ... 'f':
				cval = (cval << 4) + (c - 'a' + 10);
				break;
			case 'A' ... 'F':
				cval = (cval << 4) + (c - 'A' + 10);
				break;

			case ':':
			case '-':
				if (!sep) {
					sep = c;
				} else {
					if (sep != c)
						return (-1);
				}

				if ((pos > 5) || (cval > 0xFF))
					return (-1);

				addr[pos] = cval;
				pos++;
				cval = 0;
				break;

			case '.':
				if (!sep) {
					sep = '.';
				} else {
					if (sep != '.')
						return (-1);
				}

				if ((pos > 2) || (cval > 0xFFFF))
					return (-1);

				addr[pos << 1] = cval >> 8;
				addr[(pos << 1) + 1] = cval & 0xFF;
				pos++;				
				cval = 0;
				break;

			default:
				return (-1);
		}
	} while (orig != 0);

	if (((sep == ':') || (sep == '-')) && (pos != 6))
		return (-1);
	
	if ((sep == '.') && (pos != 3))
		return (-1);

	return (0);
}


/* print an Etherner address in colon separated hex, no newline */
void
eaprint(uint8_t *ea) {
	printf("%02x:%02x:%02x:%02x:%02x:%02x",
		ea[0], ea[1], ea[2], ea[3], ea[4], ea[5]);
}


/*
 *      fields in the Tag Control Information (TCI)
 *
 *       8   6 5 4     1 8             1
 *      +-----+-+-------+---------------+
 *      |     |C|       |               |
 *      | PCP |F|<-------- VID -------->|
 *      |     |I|       |               |
 *      +-----+-+-------+---------------+
 */

void
tci_setpcp(uint8_t pcp, uint16_t *tci) {
	/* clear PCP bits */
	*tci &= 0x1fff;
	/* set new PCP value */
	*tci |= (pcp << 13);
}

void
tci_setcfi(uint8_t cfi, uint16_t *tci) {
	if (!((cfi == 0) || (cfi == 1))) {
		fprintf(stderr, "tci_setcfi: CFI must be 0 or 1\n");
		cfi = 1;
	}
	/* set CFI bit */
	*tci |= (cfi << 8);
}

void
tci_setvid(uint16_t vid, uint16_t *tci) {
	if ((vid <= 0) || (vid >= 0xfff)) {
		fprintf(stderr, "tci_setvid: allowed VID range is 1-4094\n");
		vid = 1;
	}
	/* set VID */
	*tci = vid & 0xfff;
}

void
cfm_addencap(int vlan, uint8_t *srcmac, uint8_t *dstmac,
			uint8_t *buf, int *size) {
	int i;
	struct ether_header *p = (struct ether_header *) buf;

	/* set destination MAC address */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		p->ether_dhost[i] = dstmac[i];
	}

	/* set source MAC address */
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		p->ether_shost[i] = srcmac[i];
	}
	*size = sizeof(struct ether_header);
	
	if (vlan > 0) {
		/* set ethertype to 802.1Q tagging */
		p->ether_type = htons(ETYPE_8021Q);

		/*
		 * next 16 bits consist of:
		 * +--------+-------+---------+
		 * | 3 bits | 1 bit | 12 bits |
		 * +--------+-------+---------+
		 *     PCP     CFI      VID
		 */

		/* set PCP and CFI to zero */
		*((uint16_t *) (buf + *size)) = htons(vlan & 0xfff);
		*size += 2;

		/* set Ethernet type to CFM (0x8902) */
		*((uint16_t *) (buf + *size)) = htons(ETYPE_CFM);
		*size += 2;
	} else {
		p->ether_type = htons(ETYPE_CFM);
	}
}


/*
 *  Common CFM Header
 *                       octet
 * +------------------+
 * | MD Level         |  1 (high-order 3 bits)
 * +------------------+
 * | Version          |  1 (low-order 5 bits)
 * +------------------+
 * | Opcode           |  2
 * +------------------+
 * | Flags            |  3
 * +------------------+
 * | First TLV Offset |  4
 * +------------------+
 *
 */

void
cfm_addhdr(uint8_t md_level, uint8_t flags, uint8_t first_tlv,
					uint8_t opcode, uint8_t *buf) {

	struct cfmhdr *p = (struct cfmhdr *) buf;

	/* MD level must be in range 0-7 */
	if (md_level > 7) {
		fprintf(stderr, "cfm_addhdr: allowed MD level range is 0-7\n");
		md_level = 0;
	}
	/* set whole octet to 0, version is set to 0 too */
	p->octet1.version = DOT1AG_VERSION;
	/* MD Level is the high order 3 bits */
	p->octet1.md_level |= (md_level << 5) & 0xe0;
	p->opcode = opcode;
	p->flags = flags;
	p->tlv_offset = first_tlv;
}

/*
 * Return 1 if the frame in buf matches the expected LBR, return 0 otherwise
 */
int
cfm_matchlbr(uint8_t *buf, uint8_t *dst, uint8_t *src, uint16_t vlan,
		uint8_t md_level, uint32_t trans_id) {
	struct cfmencap *cfmencap;
	struct cfmhdr *cfmhdr;
	int i;

	cfmencap = (struct cfmencap *) buf;

	/* Check ethertype */
	if (IS_TAGGED(buf)) {
		if (cfmencap->ethertype != htons(ETYPE_CFM)) {
			return (0);
		}
	} else {
		if (cfmencap->tpid != htons(ETYPE_CFM)) {
			return (0);
		}
	}

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (cfmencap->dstmac[i] != dst[i]) {
			return (0);
		}
		if (cfmencap->srcmac[i] != src[i]) {
			return (0);
		}
	}
	cfmhdr = CFMHDR(buf);
	if (cfmhdr->opcode != CFM_LBR) {
		return (0);
	}
	return (1);
}

/*
 *  Linktrace Message Format
 *                                  octet
 *  +---------------------------+
 *  | Common CFM Header         |   1-4
 *  +---------------------------+
 *  | LTM Transaction Identifier|   5-8
 *  +---------------------------+
 *  | LTM TTL                   |    9
 *  +---------------------------+
 *  | Original MAC Address      |  10-15
 *  +---------------------------+
 *  | Target MAC Address        |  16-21
 *  +---------------------------+
 *  | Additional LTM TLVs       |
 *  +---------------------------+
 *  | END TLV (0)               |
 *  +---------------------------+
 */

void
cfm_addltm(uint32_t transID, uint8_t ttl, uint8_t *orig_mac,
                uint8_t *target_mac, uint8_t *buf) {

	struct cfm_ltm *p;
	int i;

	p = (struct cfm_ltm *) buf;
	p->transID = htonl(transID);
	p->ttl = ttl;
	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		p->orig_mac[i] = orig_mac[i];
		p->target_mac[i] = target_mac[i];
	}
}


void
cfm_ltm_setttl(uint8_t ttl, uint8_t *buf) {
	struct cfm_ltm *p;

	p = POS_CFM_LTM(buf);
	p->ttl = ttl;
}

void
cfm_ltm_settransid(uint32_t trans_id, uint8_t *buf) {
	struct cfm_ltm *p;

	p = POS_CFM_LTM(buf);
	p->transID = htonl(trans_id);
}


void
cfm_addltr(uint32_t transID, uint8_t ttl, uint8_t action, uint8_t *buf) {
	struct cfm_ltr *p;

	p = (struct cfm_ltr *) buf;
	p->transID = htonl(transID);
	p->ttl = ttl;
	p->action = action;
}


/*
 * Return 1 if the frame in buf matches the expected LTR, return 0 otherwise
 */
int
cfm_matchltr(uint8_t *buf, uint8_t *dst, uint16_t vlan, uint8_t md_level,
					uint32_t trans_id, int *hit_target) {
	struct cfmencap *encap;
	struct cfmhdr *cfmhdr;
	struct cfm_ltr *ltr;
	int i;

	encap = (struct cfmencap *) buf;

	/* Check ethertype */
	if (IS_TAGGED(buf)) {
		if (encap->ethertype != htons(ETYPE_CFM)) {
			return (0);
		}
	} else {
		if (encap->tpid != htons(ETYPE_CFM)) {
			return (0);
		}
	}	

	for (i = 0; i < ETHER_ADDR_LEN; i++) {
		if (encap->dstmac[i] != dst[i]) {
			return 0;
		}
	}
	cfmhdr = CFMHDR(buf);
	/* check if this is an LTR frame */
	if (cfmhdr->opcode != CFM_LTR) {
		return 0;
	}
	ltr = (struct cfm_ltr *) POS_CFM_LTR(buf);
	/* check for correct nextTransID */
	if (ntohl(ltr->transID) != trans_id) {
		return 0;
	}

	if (ltr->action == ACTION_RLYHIT) {
		*hit_target = 1;
	}
	return 1;
}
