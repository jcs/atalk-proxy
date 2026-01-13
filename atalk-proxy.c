/*
 * Copyright (c) 2026 joshua stein <jcs@jcs.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <ifaddrs.h>
#include <pcap.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <pcap/bpf.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#elif defined(__OpenBSD__)
#include <net/bpf.h>
#include <net/if_dl.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#define	MIN(a,b) (((a)<(b))?(a):(b))

enum {
	IFACE_EGRESS,
	IFACE_TAP,
};

static char errbuf[PCAP_ERRBUF_SIZE];
static char *ifaces[2] = { NULL };
static unsigned char emac[6];
static pcap_t *pcaps[2];
static int debug = 0;

uint16_t be16(const unsigned char *);
uint32_t be24(const unsigned char *);
pcap_t * sniff(char *, char *);
void usage(void);
char * ts(void);
void forward(u_char *, const struct pcap_pkthdr *, const u_char *);
void inspect(unsigned char *, size_t);
int mac(const char *, unsigned char *);

void
usage(void)
{
	printf("usage: atalk-proxy [-d] -e <egress iface> -t <tap iface>\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	struct pollfd pfd[3];
	int ch, n, nready;
#ifdef __OpenBSD__
	int cmplt;
#endif

	while ((ch = getopt(argc, argv, "de:t:")) != -1) {
		switch (ch) {
		case 'd':
			debug++;
			break;
		case 'e':
			if ((ifaces[IFACE_EGRESS] = strdup(optarg)) == NULL)
				err(1, "strdup");
			break;
		case 't':
			if ((ifaces[IFACE_TAP] = strdup(optarg)) == NULL)
				err(1, "strdup");
			break;
		default:
			usage();
		}
	}

	if (ifaces[IFACE_TAP] == NULL || ifaces[IFACE_EGRESS] == NULL)
		usage();

	for (n = 0; n < 2; n++) {
		/* look for LLC SNAP packets, or bare AARP */
		pcaps[n] = sniff(ifaces[n],
		    "(ether[14] == 0xaa && ether[15] == 0xaa) or "
		    "(ether[12] == 0x80 && ether[13] == 0xf3)"
		);

		pfd[n].fd = pcap_get_selectable_fd(pcaps[n]);
		pfd[n].events = POLLIN;

#ifdef __OpenBSD__
		/* set BIOCSHDRCMPLT so we can change link-level source MAC */
		cmplt = 1;
		if (ioctl(pfd[n].fd, BIOCSHDRCMPLT, &cmplt) == -1)
			err(1, "failed setting BIOCSHDRCMPLT on %s",
			    ifaces[n]);
#endif

		if (n == IFACE_EGRESS) {
			if (mac(ifaces[n], (unsigned char *)&emac) == -1)
				errx(1, "failed getting MAC of %s", ifaces[n]);

			if (debug)
				printf("[%s] [%s] listening on egress using "
				    "outbound MAC "
				    "%02x:%02x:%02x:%02x:%02x:%02x\n",
				    ts(), ifaces[n], emac[0], emac[1], emac[2],
				    emac[3], emac[4], emac[5]);
		} else if (debug) {
			printf("[%s] [%s] listening on tap\n", ts(), ifaces[n]);
		}
	}

#ifdef __OpenBSD__
	if (pledge("stdio", NULL) == -1)
		err(1, "pledge");
#else
	warnx("no pledge support");
#endif

	for (;;) {
		nready = poll(pfd, 2, 60 * 1000);
		if (nready == -1)
			err(1, "poll");

		for (n = 0; n < 2; n++) {
			if (pfd[n].revents & (POLLERR|POLLNVAL)) {
				warnx("[%s] poll on %s has errors\n", ts(),
				    ifaces[n]);
				break;
			}
			if ((pfd[n].revents & (POLLIN|POLLHUP)))
				pcap_dispatch(pcaps[n], -1, forward,
				    (u_char *)&n);
		}
	}

	for (n = 0; n < 2; n++)
		pcap_close(pcaps[n]);

	return 0;
}

pcap_t *
sniff(char *iface, char *filter)
{
	struct bpf_program fp;
	pcap_t *handle;

	if ((handle = pcap_create(iface, errbuf)) == NULL)
		err(1, "pcap_create");

	if (pcap_set_immediate_mode(handle, 1) == -1)
		errx(1, "pcap_setnonblock: %s", pcap_geterr(handle));

	if (pcap_activate(handle) == -1)
		errx(1, "pcap_activate: %s", pcap_geterr(handle));

	if (pcap_setdirection(handle, PCAP_D_IN) == -1)
		err(1, "pcap_setdirection");

	if (pcap_compile(handle, &fp, filter, 0, 0) == -1)
		errx(1, "pcap_compile: %s", pcap_geterr(handle));

	if (pcap_setfilter(handle, &fp) == -1)
		errx(1, "pcap_setfilter: %s", pcap_geterr(handle));

	if (pcap_setnonblock(handle, 1, errbuf) == -1)
		errx(1, "pcap_setnonblock: %s", pcap_geterr(handle));

	return handle;
}

int
mac(const char *ifname, unsigned char *mac)
{
	struct ifaddrs *ifap, *ifa;
#ifdef __linux__
	struct sockaddr_ll *sll;
#elif defined(__OpenBSD__)
	struct sockaddr_dl *sdl;
#endif
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return -1;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
#ifdef __linux__
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_PACKET ||
		    strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		sll = (struct sockaddr_ll *)ifa->ifa_addr;
		if (sll->sll_halen == 6) {
			memcpy(mac, sll->sll_addr, 6);
			found = 1;
			break;
		}
#else
		if (ifa->ifa_addr == NULL ||
		    ifa->ifa_addr->sa_family != AF_LINK ||
		    strcmp(ifa->ifa_name, ifname) != 0)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_alen == 6) {
			memcpy(mac, LLADDR(sdl), 6);
			found = 1;
			break;
		}
#endif
	}

	freeifaddrs(ifap);
	return found ? 0 : -1;
}

uint16_t
be16(const unsigned char *b)
{
	return ((unsigned)b[0] << 8) | b[1];
}

uint32_t
be24(const unsigned char *b)
{
	return ((unsigned)b[0] << 16) | ((unsigned)b[1] << 8) | b[2];
}

char *
ts(void)
{
	static char ret[25], ti[20];
	struct timespec ts;
	struct tm *tm;
	long msec;

	clock_gettime(CLOCK_REALTIME, &ts);
	if (ts.tv_nsec >= 999500000) {
		ts.tv_sec++;
		msec = 0;
	} else
		msec = (ts.tv_nsec + 500000) / 1000000;

	tm = localtime(&ts.tv_sec);
	strftime(ti, sizeof(ti), "%H:%M:%S", tm);
	snprintf(ret, sizeof(ret), "%s.%03i", ti, (int)msec);

	return ret;
}

void
forward(u_char *user, const struct pcap_pkthdr *h, const u_char *b)
{
	static unsigned char mb[1500];
	size_t len;
	int iface = (int)*user;
	int ret, oface;

	len = h->len;
	if (len > sizeof(mb))
		len = sizeof(mb);
	memcpy(mb, b, len);

	oface = (iface == IFACE_TAP ? IFACE_EGRESS : IFACE_TAP);

	if (debug)
		printf("[%s] [%s] [%3d]", ts(), ifaces[iface], h->len);

	if (be16(b + 12) == 0x80f3) {
		/* bare AARP packet with no LLC header, insert it */
		if (debug > 1)
			printf(" bare AARP, inserting LLC:");

		mb[14] = 0xaa; /* DSAP: SNAP */
		mb[15] = 0xaa; /* SSAP: SNAP */
		mb[16] = 0x03; /* control */

		mb[17] = 0x00;
		mb[18] = 0x00;
		mb[19] = 0x00; /* org: none */

		mb[20] = 0x80;
		mb[21] = 0xf3; /* type: aarp */

		/* append AARP */
		memcpy(mb + 22, b + 14, h->len - 14);
		len = h->len + 8;

		/* fix length */
		mb[12] = 0x00;
		mb[13] = len - 12 - 2;
	}

	if (debug)
		inspect(mb, len);

	if (iface == IFACE_TAP) {
		/* replace source MAC from tap packet with egress's */
		memcpy(mb + 6, emac, 6);

		/* for AARP replies we're sending, replace MAC with egress */
		if (mb[14] == 0xaa /* DSAP: SNAP */ &&
		    mb[15] == 0xaa /* SSAP: SNAP */ &&
		    be16(mb + 20) == 0x80f3 /* type: AARP */ &&
		    be16(mb + 28) == 0x0002 /* op: reply */) {
			if (debug)
				printf(": replacing MAC in outbound AARP reply");
			memcpy(mb + 30, emac, 6);
		}
	}

	if (debug)
		printf(" [-> %s]\n", ifaces[oface]);

	ret = pcap_inject(pcaps[oface], mb, len);
	if (ret != (int)len)
		warn("pcap_inject to %s: %s", ifaces[oface],
		    pcap_geterr(pcaps[oface]));
}

void
inspect(unsigned char *pkt, size_t len)
{
	size_t tlen, j;
	unsigned i, n, op, count;
	uint16_t pid;

	printf(" ");

	if (len < 22) {
		printf("bogus length %zu", len);
		return;
	}

	if (pkt[14] != 0xaa) {
		printf("DSAP 0x%x != SNAP", pkt[14]);
		return;
	}

	if (pkt[15] != 0xaa) {
		printf("SSAP 0x%x != SNAP", pkt[15]);
		return;
	}

	switch (pid = be16(pkt + 20)) {
	case 0x80f3:
		printf("AARP: ");

		switch (op = be16(pkt + 28)) {
		case 1:
			/* request */
			printf("who has %d.%d? tell %d.%d",
			    be24(pkt + 38), pkt[41], be24(pkt + 28), pkt[31]);
			break;
		case 2:
			/* reply */
			printf("%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x",
			    be24(pkt + 36), pkt[41],
			    pkt[30], pkt[31], pkt[32], pkt[33], pkt[34],
			    pkt[35]);
			break;
		case 3:
			/* probe */
			printf("is there a %d.%d?", be24(pkt + 46), pkt[49]);
			break;
		default:
			printf("unknown operation 0x%02x", op);
		}
		return;
	case 0x809b:
		/* AppleTalk DDP, handled below */
		break;
	default:
		printf("unknown LLC PID 0x%04x", pid);
		return;
	}

	/* AppleTalk DDP */

	switch (pkt[34]) {
	case 2:
		/* AppleTalk Name Binding Protocl */
		printf("NBP: ");
		count = pkt[35] & 0xf;

		switch (pkt[35] >> 4) {
		case 2:
			printf("lookup: ");
			break;
		case 3:
			printf("reply[%d]: ", count);
			break;
		default:
			printf("unknown operation %d", pkt[35] >> 4);
			return;
		}

		n = 37;
		for (i = 0; i < count; i++) {
			if (i > 0)
				printf(", ");

			/* network, node, port, enumerator */
			n += 2 + 1 + 1 + 1;

			/* object */
			printf("\"");
			tlen = pkt[n++];
			if (n + tlen > len)
				goto overflow;
			for (j = 0; j < tlen; j++, n++)
				printf("%c", pkt[n]);

			/* type */
			printf(":");
			tlen = pkt[n++];
			if (n + tlen > len)
				goto overflow;
			for (j = 0; j < tlen; j++, n++)
				printf("%c", pkt[n]);

			/* zone */
			printf("@");
			tlen = pkt[n++];
			if (n + tlen > len)
				goto overflow;
			for (j = 0; j < tlen; j++, n++)
				printf("%c", pkt[n]);
			printf("\"");
		}
		break;
overflow:
		printf(" [overflow %zu > %zu]", n + tlen, len);
		break;
	case 3:
		/* transaction protocol */
		printf("transaction protocol");
		/* TODO */
		break;
	case 4:
		printf("echo from %d.%d to %d.%d", be16(pkt + 28), pkt[31],
		    be16(pkt + 26), pkt[30]);
		break;
	case 6:
		printf("ZIP: ");
		switch (pkt[35]) {
		case 5:
			printf("GetNetInfo");
			break;
		default:
			printf(": unknown ZIP function %d", pkt[35]);
			break;
		}
		break;
	default:
		printf("unknown DDP protocol %d", pkt[34]);
		break;
	}
}
