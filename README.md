# atalk-proxy

`atalk-proxy` listens for AppleTalk DDP (Datagram Delivery Protocol) and
AARP (AppleTalk Address Resolution Protocol) traffic on two ethernet interfaces
and proxies packets between them.

There are other solutions for this such as
[multitalk](https://github.com/sfiera/multitalk)
but this one has a few features I needed:

- It does not require kernel or libpcap support for AppleTalk, as is the
  situation on OpenBSD.  Packets are found by looking for specific bytes in the
  header.

- It drops privileges after opening listening sockets using
  [`pledge`](https://man.openbsd.org/pledge).

- Bare AARP packets that appear on the wire without a Logical-Link Control
  header are given an LLC encapsulation before proxying.

- AARP replies that are sent out from the local side (`-t`) are inspected and
  the MAC address of the sender is replaced with the MAC of the egress (`-e`)
  interface.
  This works as a
  "[proxy ARP](https://en.wikipedia.org/wiki/Proxy_ARP)"
  solution so other network devices know to send traffic to the device running
  the proxy to reach devices on the proxy's other interface, which is likely
  needed on Wi-Fi networks.

## Installation

	$ git clone https://github.com/jcs/atalk-proxy
	$ cd atalk-proxy
	$ make

`atalk-proxy` was written on OpenBSD and has only been tested there.

## Usage

When using an emulated Macintosh Plus in
[pce](https://github.com/jcs/pce)
on my laptop, configured with an emulated DaynaPort SCSI ethernet device, and
configured to use EtherTalk for AppleTalk traffic, it sends packets out through
a
[`tap`](https://man.openbsd.org/tap)
interface on my laptop.

I then run `atalk-proxy` to proxy traffic between that `tap0` interface and my
laptop's wireless `iwx0` interface.
That usage for me looks like:

	$ doas ./atalk-proxy -e iwx0 -t tap0

This enables the emulated device to communicate with other devices on my
network using AppleTalk.

The `-d` flag can be used to print debugging information where each forwarded
packet is described.

	$ doas ./atalk-proxy -d -e iwx0 -t tap0
	[12:47:35.599] [iwx0] listening on egress using outbound MAC 00:d4:9e:x:x:x
	[12:47:35.599] [tap0] listening on tap
	[12:47:45.386] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:45.741] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:46.072] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:46.402] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:46.734] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:47.063] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:47.420] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:47.735] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:48.067] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:48.396] [tap0] [ 50] AARP: is there a 65512.1? [-> iwx0]
	[12:47:48.750] [tap0] [ 42] ZIP: GetNetInfo [-> iwx0]
	[12:47:49.566] [tap0] [ 42] ZIP: GetNetInfo [-> iwx0]
	[12:47:50.404] [tap0] [ 42] ZIP: GetNetInfo [-> iwx0]
	[12:47:51.270] [tap0] [ 67] NBP: lookup: "nanomac:Macintosh Plus@*" [-> iwx0]
	[12:47:52.324] [tap0] [ 67] NBP: lookup: "nanomac:Macintosh Plus@*" [-> iwx0]
	[12:47:53.231] [tap0] [ 67] NBP: lookup: "nanomac:Macintosh Plus@*" [-> iwx0]
	[12:47:57.418] [tap0] [ 56] NBP: lookup: "=:AFPServer@*" [-> iwx0]
	[12:47:57.580] [iwx0] [ 42] AARP: who has 57344.0? tell 256.12 [-> tap0]
	[12:47:57.610] [tap0] [ 50] AARP: 65512.12 is at 00:80:19:c0:c0:c0: replacing MAC in outbound AARP reply [-> iwx0]
	[12:47:57.612] [iwx0] [ 57] NBP: reply[1]: "fs:AFPServer@*" [-> tap0]
	[12:47:58.593] [tap0] [621] echo from 65512.1 to 65280.224 [-> iwx0]
	[12:47:58.596] [iwx0] [621] echo from 65280.224 to 65512.1 [-> tap0]
	[12:47:58.622] [tap0] [ 43] transaction protocol [-> iwx0]
	[12:47:58.628] [iwx0] [470] transaction protocol [-> tap0]
	[12:47:59.134] [tap0] [ 56] NBP: lookup: "=:AFPServer@*" [-> iwx0]
	[12:47:59.443] [iwx0] [ 57] NBP: reply[1]: "fs:AFPServer@*" [-> tap0]
	[12:48:00.337] [tap0] [ 43] transaction protocol [-> iwx0]
