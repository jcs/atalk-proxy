#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <err.h>
#include <limits.h>
#include <string.h>
#include <poll.h>
#include <pcap.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if_dl.h>

#define	MIN(a,b) (((a)<(b))?(a):(b))

enum {
	IFACE_TAP,
	IFACE_WIFI,
};

struct pcap_pkthdr header;
const u_char *packet;
char errbuf[PCAP_ERRBUF_SIZE];
char *ifaces[2] = { NULL };
unsigned char macs[2][6];
pcap_t *pcaps[2];

pcap_t * sniff(char *, char *);
void usage(void);
void debug(char *, ...);
void packet_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
int mac(const char *, unsigned char *);

void
usage(void)
{
	printf("usage: atalk-proxy -t <tap iface> -w <wifi iface>\n");
	exit(1);
}

void
debug(char *fmt, ...)
{
	va_list ap;
	struct timespec ts;
	struct tm *tm;
	char ti[25];
	long msec;

	clock_gettime(CLOCK_REALTIME, &ts);
	if (ts.tv_nsec >= 999500000) {
		ts.tv_sec++;
		msec = 0;
	} else
		msec = (ts.tv_nsec + 500000) / 1000000;

	tm = localtime(&ts.tv_sec);
	strftime(ti, sizeof(ti), "%H:%M:%S", tm);
	printf("[%s.%03li] ", ti, msec);

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}

int
main(int argc, char *argv[])
{
	struct pollfd pfd[3];
	int ch, n, nready, cmplt;

	while ((ch = getopt(argc, argv, "t:w:")) != -1) {
		switch (ch) {
		case 't':
			if ((ifaces[IFACE_TAP] = strdup(optarg)) == NULL)
				err(1, "strdup");
			break;
		case 'w':
			if ((ifaces[IFACE_WIFI] = strdup(optarg)) == NULL)
				err(1, "strdup");
			break;
		default:
			usage();
		}
	}

	if (ifaces[IFACE_TAP] == NULL || ifaces[IFACE_WIFI] == NULL)
		usage();

	for (n = 0; n < 2; n++) {
		pcaps[n] = sniff(ifaces[n],
		    "(ether[14] == 0xaa && ether[15] == 0xaa) or " /* SNAP */
		    "(ether[12] == 0x80 && ether[13] == 0xf3)"	   /* AARP */
		);

		pfd[n].fd = pcap_get_selectable_fd(pcaps[n]);
		pfd[n].events = POLLIN;

		/* set BIOCSHDRCMPLT so we can change link-level source MAC */
		cmplt = 1;
		if (ioctl(pfd[n].fd, BIOCSHDRCMPLT, &cmplt) == -1)
			err(1, "failed setting BIOCSHDRCMPLT on %s",
			    ifaces[n]);
		if (mac(ifaces[n], (unsigned char *)&macs[n]) == -1)
			errx(1, "failed getting MAC of %s", ifaces[n]);
	}

	for (;;) {
		nready = poll(pfd, 2, 60 * 1000);
		if (nready == -1)
			err(1, "poll");

		for (n = 0; n < 2; n++) {
			if (pfd[n].revents & (POLLERR|POLLNVAL)) {
				debug("pfd[%d] has errors\n", n);
				break;
			}
			if ((pfd[n].revents & (POLLIN|POLLHUP)))
				pcap_dispatch(pcaps[n], -1, packet_handler,
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
	bpf_u_int32 mask = 0, net = 0;

	if ((handle = pcap_create(iface, errbuf)) == NULL)
		err(1, "pcap_create");

	if (pcap_set_immediate_mode(handle, 1) == -1)
		errx(1, "pcap_setnonblock: %s", pcap_geterr(handle));

	if (pcap_activate(handle) == -1)
		errx(1, "pcap_activate: %s", pcap_geterr(handle));

	if (pcap_setdirection(handle, PCAP_D_IN) == -1)
		err(1, "pcap_setdirection");

	if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1)
		warn("pcap_lookupnet(\"%s\"): %s", iface, errbuf);

	if (pcap_compile(handle, &fp, filter, 0, 0) == -1)
		errx(1, "pcap_compile: %s", pcap_geterr(handle));

	if (pcap_setfilter(handle, &fp) == -1)
		errx(1, "pcap_setfilter: %s", pcap_geterr(handle));

	if (pcap_setnonblock(handle, 1, errbuf) == -1)
		errx(1, "pcap_setnonblock: %s", pcap_geterr(handle));

	return handle;
}

void
packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
	static unsigned char mbytes[1500];
	int iface = (int)*user;
	int n, j, len, ret, oface;

	len = h->len;
	if (len > sizeof(mbytes))
		len = sizeof(mbytes);
	memcpy(mbytes, bytes, len);

	oface = (iface == IFACE_TAP ? IFACE_WIFI : IFACE_TAP);

	debug("[%s %zu]", ifaces[iface], h->len);

	if (bytes[12] == 0x80 && bytes[13] == 0xf3) {
		/* bare AARP packet with no LLC, insert LLC */
		mbytes[14] = 0xaa; /* DSAP: SNAP */
		mbytes[15] = 0xaa; /* SSAP: SNAP */
		mbytes[16] = 0x03; /* control */

		mbytes[17] = 0x00;
		mbytes[18] = 0x00;
		mbytes[19] = 0x00; /* org: none */

		mbytes[20] = 0x80;
		mbytes[21] = 0xf3; /* type: aarp */

		/* append AARP */
		memcpy(mbytes + 22, bytes + 14, h->len - 14);
		len = h->len + 8;

		/* fix length */
		mbytes[12] = 0x00;
		mbytes[13] = len - 12 - 2;
	}

	if (bytes[12] == 0x80 && bytes[13] == 0xf3) {
		printf(" AARP");

		/* opcode: request */
		printf(": who has %d.%d?  tell %d.%d",
		    ((int)bytes[38] << 16) | (int)bytes[39] << 8 | bytes[40],
		    bytes[41],
		    ((int)bytes[28] << 16) | (int)bytes[29] << 8 | bytes[30],
		    bytes[31]);
	} else if (bytes[14] == 0xaa) {
		/* DSAP: SNAP */
		printf(" SNAP");

		if (bytes[15] != 0xaa)
			goto relay;

		/* SSAP: SNAP */

		if (bytes[20] != 0x80 || bytes[21] != 0x9b)
			goto relay;

		if (bytes[34] != 2)
			goto relay;

		/* NBP */
		n = 42;
		printf(": \"");
		while (n < h->len) {
			len = bytes[n++];
			if (n + len > h->len) {
				printf(" (overflow %d > %d)", n + len, h->len);
				goto relay;
			}
			for (j = 0; j < len; j++, ++n)
				printf("%c", bytes[n]);
		}
		printf("\"");

		len = h->len;
		goto relay;
	}

relay:
	if (oface == IFACE_WIFI) {
		/* replace source MAC from tap packet with wifi's */
		memcpy(mbytes + 6, macs[IFACE_WIFI], 6);

		/* if this is an AARP reply, pretend we're at the wifi's MAC */
		if (mbytes[14] == 0xaa /* DSAP: SNAP */ &&
		    mbytes[15] == 0xaa /* SSAP: SNAP */ &&
		    mbytes[20] == 0x80 && mbytes[21] == 0xf3 /* type: AARP */ &&
		    mbytes[28] == 0x00 && mbytes[29] == 0x02 /* op: reply */ &&
		    memcmp(mbytes + 30, macs[IFACE_TAP], 6) == 0) {
			printf(": AARP reply, replacing MAC");
			memcpy(mbytes + 30, macs[IFACE_WIFI], 6);
		}
	}

	printf(" [-> %s %u]\n", ifaces[oface], len);

	ret = pcap_inject(pcaps[oface], mbytes, len);
	if (ret != len)
		warn("pcap_inject to %s: %s", ifaces[oface],
		    pcap_geterr(pcaps[oface]));
}

int
mac(const char *ifname, unsigned char *mac)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl;
	int found = 0;

	if (getifaddrs(&ifap) != 0)
		return -1;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
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
	}

	freeifaddrs(ifap);
	return found ? 0 : -1;
}
