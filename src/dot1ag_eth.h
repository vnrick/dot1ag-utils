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

#include <pcap.h>

#define SNAPLEN		65535	/* pcap snap length */

#ifdef HAVE_NET_BPF_H

/*
 * FreeBSD has /dev/bpf als clone interface
 * MacOSX has /dev/bpf0, /dev/bpf1, ...
 */

#define NR_BPF_IFS	6
#define BPF_IFS_MAXLEN	10

#endif

int
get_local_mac(char *dev, uint8_t *ea);

int
send_packet(char *ifname, uint8_t *buf, int size);

int
cfm_waitfor_lbr(pcap_t *handle, struct timeval time_sent,
	struct timeval timeout, uint8_t *dst, uint8_t *src,
	int vlan, uint8_t md_level, uint32_t trans_id);

int
cfm_send_lbr(char *ifname, uint8_t *buf, int size);

int
processLTM(char *ifname, uint8_t *ltm_frame);

void
cfm_ccm_sender(char *ifname, uint16_t vlan, uint8_t md_level, char *md,
			char *ma, uint16_t mepid, int interval);

void
print_ltr(uint8_t *buf);
