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

/*
 * CFM PDU Encapsulation with type/length media
 */

#include <stdint.h>
#include <netinet/in.h>
#include <sys/types.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif
#ifdef HAVE_NET_IF_ETHER_H
#include <net/if.h>
#include <net/if_ether.h>
#endif

/* compare timevals a to b using the comparison operator given in cmp */
#define cfm_timevalcmp(a, b, cmp)		\
	((a.tv_sec == b.tv_sec) ?	\
	(a.tv_usec cmp b.tv_usec) :	\
	(a.tv_sec cmp b.tv_sec))

#define ETYPE_8021Q	0x8100
#define ETYPE_CFM	0x8902

#define ETHER_DOT1Q_LEN		4		/* size of 802.1Q hdr */
#define ETHER_IS_MCAST(s)	(*(s) & 0x01)	/* is address mcast/bcast? */

/* return true if MAC address 's' belongs to the CCM multicast group */
/* 01:80:C2:00:00:3y, where 0 <= y < 8 */
#define ETHER_IS_CCM_GROUP(s)	((*(s) == 0x01) && \
				(*(s + 1) == 0x80) && \
				(*(s + 2) == 0xc2) && \
				(*(s + 3) == 0x00) && \
				(*(s + 4) == 0x00) && \
				((*(s + 5) & 0xF8) == 0x30))

/* return true if MAC address 's' belongs to the LTM multicast group */
/* 01:80:C2:00:00:3y, where 8 <= y <= F */
#define ETHER_IS_LTM_GROUP(s)	((*(s) == 0x01) && \
				(*(s + 1) == 0x80) && \
				(*(s + 2) == 0xc2) && \
				(*(s + 3) == 0x00) && \
				(*(s + 4) == 0x00) && \
				((*(s + 5) & 0xF8) == 0x38))

/* return true is 'x' and 'y' are the same MAC address */
#define ETHER_IS_EQUAL(x, y)	((*(x) == *(y)) && \
				(*(x + 1) == *(y + 1)) && \
				(*(x + 2) == *(y + 2)) && \
				(*(x + 3) == *(y + 3)) && \
				(*(x + 4) == *(y + 4)) && \
				(*(x + 5) == *(y + 5)))

#define DOT1AG_VERSION		0

/* Parse a MAC address */
int
eth_addr_parse(uint8_t *addr, char *str);

/* print an Etherner address in colon separated hex, no newline */
void
eaprint(uint8_t *ea);

struct cfmencap {
	uint8_t dstmac[ETHER_ADDR_LEN];
	uint8_t srcmac[ETHER_ADDR_LEN];
	uint16_t tpid;
	uint16_t tci;
	uint16_t ethertype;
} __attribute__ ((__packed__));

void
tci_setpcp(uint8_t pcp, uint16_t *tci);

void
tci_setcfi(uint8_t cfi, uint16_t *tci);

void
tci_setvid(uint16_t vid, uint16_t *tci);

void
cfm_addencap(int vlan, uint8_t *src, uint8_t *dst,
				uint8_t *buf, int *size);

/*
 * CFM opcodes
 */

#define CFM_CCM	1
#define CFM_LBR 2
#define CFM_LBM 3
#define CFM_LTR 4
#define CFM_LTM 5

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

struct cfmhdr {
	union {
		uint8_t md_level;   /* high order 3 bits */
		uint8_t version;    /* low order 5 bits */
	} octet1;
	uint8_t opcode;
	uint8_t flags;
	uint8_t tlv_offset;
} __attribute__ ((__packed__));

/* LTM/LTR Flags */
#define DOT1AG_LTFLAGS_USEFDBONLY	0x80;
#define DOT1AG_LTFLAGS_FWDYES		0x40;
#define DOT1AG_LTFLAGS_TERMINALMEP	0x20;

#define FIRST_TLV_CCM	70
#define FIRST_TLV_LBM	4
#define FIRST_TLV_LBR	4
#define FIRST_TLV_LTM	17
#define FIRST_TLV_LTR	6

void
cfm_addhdr(uint8_t md_level, uint8_t flags, uint8_t first_tlv,
					uint8_t opcode, uint8_t *buf);

struct cfm_lbm {
	uint32_t trans_id;
};

/* TLV codes */
#define TLV_END				0
#define TLV_SENDER_ID			1
#define TLV_PORT_STATUS			2
#define TLV_DATA			3
#define TLV_INTERFACE_STATUS		4
#define TLV_REPLY_INGRESS		5
#define TLV_REPLY_EGRESS		6
#define TLV_LTM_EGRESS_IDENTIFIER	7
#define TLV_LTR_EGRESS_IDENTIFIER	8
#define TLV_ORG_SPECIFIC		31

/* Port Status TLV values */
#define DOT1AG_PS_BLOCKED		1
#define DOT1AG_PS_UP			2

/* Interface Status TLV values */
#define DOT1AG_IS_UP			1
#define DOT1AG_IS_DOWN			2
#define DOT1AG_IS_TESTING		3
#define DOT1AG_IS_UNKNOWN		4
#define DOT1AG_IS_DORMANT		5
#define DOT1AG_IS_NOTPRESENT		6
#define DOT1AG_IS_LOWERLAYERDOWN	7

/* Ingress Action */
#define DOT1AG_IngOK			1
#define DOT1AG_IngDown			2
#define DOT1AG_IngBlocked		3
#define DOT1AG_IngVID			4

/* return the VLAN ID in a struct encap */
#define GET_VLAN(s)		(ntohs((s)->tci) & 0x0fff)

/* return the MD Level in a struct cfmhdr */
#define GET_MD_LEVEL(s)		(((s)->octet1.md_level >> 5) & 0x07)

/* positions of headers in Ethernet frame */
#define IS_TAGGED(s)		(*(s + ETHER_ADDR_LEN * 2) \
					== htons(ETYPE_8021Q))
#define CFMHDR(s)		(struct cfmhdr *) \
				(IS_TAGGED(s) ? \
					((s) + ETHER_HDR_LEN + \
					ETHER_DOT1Q_LEN) : \
					((s) + ETHER_HDR_LEN))
#define CFMHDR_U8(s,x)          ((uint8_t *)CFMHDR((s)) + (x))

#define POS_CFM_LTM(s)		(struct cfm_ltm *) \
				(CFMHDR_U8((s),sizeof(struct cfmhdr)))

#define POS_CFM_LTR(s)		(struct cfm_ltr *) \
				(CFMHDR_U8((s),sizeof(struct cfmhdr)))

#define POS_CFM_CC(s)		(struct cfm_cc *) \
				(CFMHDR_U8((s),sizeof(struct cfmhdr)))

#define POS_CFM_CC_TLVS(s)	(uint8_t *) \
				(CFMHDR_U8((s),sizeof(struct cfmhdr) + \
				sizeof(struct cfm_cc)))

int
cfm_matchlbr(uint8_t *buf, uint8_t *dst, uint8_t *src, uint16_t vlan,
		uint8_t md_level, uint32_t trans_id);


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
 *  | End TLV (0)               |
 *  +---------------------------+
 */

struct cfm_ltm {
	uint32_t transID;
	uint8_t	 ttl;
	uint8_t orig_mac[ETHER_ADDR_LEN];
	uint8_t target_mac[ETHER_ADDR_LEN];
} __attribute__ ((__packed__));

#define ETHER_CFM_GROUP		"01:80:C2:00:00:30"

void
cfm_addltm(uint32_t transID, uint8_t ttl, uint8_t *localmac,
                uint8_t *remotemac, uint8_t *buf);


/*
 *  Linktrace Reply Format
 *                                  octet
 *  +---------------------------+
 *  | Common CFM Header         |   1-4
 *  +---------------------------+
 *  | LTM Transaction Identifier|   5-8
 *  +---------------------------+
 *  | LTM TTL                   |    9
 *  +---------------------------+
 *  | Relay Action              |    10
 *  +---------------------------+
 *  | Additional LTR TLVs       |
 *  +---------------------------+
 *  | End TLV (0)               |
 *  +---------------------------+
 */

struct cfm_ltr {
	uint32_t transID;
	uint8_t ttl;
	uint8_t action;
} __attribute__ ((__packed__));

#define ACTION_RLYHIT	1
#define ACTION_RLYFDB	2
#define ACTION_RLYMPDB	3


void
cfm_ltm_setttl(uint8_t ttl, uint8_t *buf);

void
cfm_ltm_settransid(uint32_t trans_id, uint8_t *buf);

void
cfm_addltr(uint32_t transID, uint8_t ttl, uint8_t action, uint8_t *buf);

int
cfm_matchltr(uint8_t *buf, uint8_t *dst, uint16_t vlan, uint8_t md_level,
					uint32_t trans_id, int *hit_target);


/*
 *  Continuity Check Message Format
 *                                                      octet
 *  +----------------------------------------------+
 *  | Common CFM Header                            |    1-4
 *  +----------------------------------------------+
 *  | Sequence Number                              |    5-8
 *  +----------------------------------------------+
 *  | Maintenance Association End Point Identifier |    9-10
 *  +----------------------------------------------+
 *  | Maintenance Association Identifier (MAID)    |    11-58
 *  +----------------------------------------------+
 *  | Defined by ITU-T Y.1731                      |    59-74
 *  +----------------------------------------------+
 *  | Reserved                                     |
 *  +----------------------------------------------+
 *  | Optional CCM TLVs                            |
 *  +----------------------------------------------+
 *  | End TLV (0)                                  |
 *  +----------------------------------------------+
 */

#define DOT1AG_MAX_MD_LENGTH		43

struct cfm_maid {
	uint8_t		format;		/* MD Name Format */
	uint8_t		length;		/* MD Name Length */
	uint8_t		var_p[46];	/* variable part */
} __attribute__ ((__packed__));

#define MAID_SIZE	sizeof(struct cfm_maid)

struct cfm_cc {
	uint32_t	seqNumber;	/* Sequence Number */
	uint16_t	mepid;		/* MA End Point Identifier */
	struct cfm_maid	maid;		/* Maintenance Association ID */
	uint8_t		y1731[16];	/* ITU-T Y.1731 part, all zero */
} __attribute__ ((__packed__));


/* CCM receiver variables */

#define MAX_MEPID        8191

struct rMEP {
	int active;
	int CCMreceivedEqual;
	uint8_t recvdMacAddress[ETHER_ADDR_LEN];
	int recvdRDI;
	int rMEPCCMdefect;
	struct timeval rMEPwhile;
	int recvdInterval;
	int tlv_ps;   /* TLV Port Status */
	int tlv_is;   /* TLV Interface Status */
};
