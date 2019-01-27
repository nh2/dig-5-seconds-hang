## Problem

Some DNS requests on my machine take 5 seconds when a specific network interface is used.

I suspect this is a problem in the kernel, somewhere between the iptables layer and the level on which Wireshark/tcpdump operates.

I give the reasoning for this suspicion below.

It happens in around 5% of the invocations of `dig ifconfig.me @1.1.1.1`.
(It doesn't matter which nameserver or domain is used, I'm just using `1.1.1.1` as an example because it can be nicely grepped in logs.)
My usual DNS resolution time is 1 ms.

I can reproduce the problem in less than 1 second by running `while true; do date; time dig ifconfig.me @1.1.1.1; done`.
A couple successful invocations flush by, then `dig` hangs for 5 seconds.

I'm fairly certain 5 seconds is a timeout implemented by `dig`/`glibc`; it's what it does when it doesn't get a response to its UDP requests.

`strace` demonstrates that the userspace side does what it should:

```
sendmsg(20<socket:[92070424]>, {msg_name(16)={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_iov(1)=[{"\372\f\1 \0\1\0\0\0\0\0\1\10ifconfig\2me\0\0\1\0\1\0\0)"..., 40}], msg_controllen=0, msg_flags=0}, 0) = 40
epoll_wait(
  -- here it hangs
  -- 5 seconds hang here
<... futex resumed> )       = -1 ETIMEDOUT (Connection timed out)
  -- dig's 5 second timeout triggers, it retries
sendmsg(20<socket:[92070424]>, {msg_name(16)={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_iov(1)=[{"\372\f\1 \0\1\0\0\0\0\0\1\10ifconfig\2me\0\0\1\0\1\0\0)"..., 40}], msg_controllen=0, msg_flags=0}, 0) = 40
  -- 1 ms later
recvmsg(20<socket:[92070424]>, {msg_name(16)={sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("8.8.8.8")}, msg_iov(1)=[{"\372\f\201\200\0\1\0\4\0\0\0\1\10ifconfig\2me\0\0\1\0\1\300\f\0"..., 65535}], msg_controllen=56, [{cmsg_len=32, cmsg_level=SOL_SOCKET, cmsg_type=0x1d /* SCM_??? */}, {cmsg_len=17, cmsg_level=SOL_IP, cmsg_type=IP_TOS, {tos=0}}], msg_flags=0}, 0) = 104
```

I have recorded this in Wireshark.
It displays only 1 DNS request being made / UDP packet being sent, not 2, even though the userspace program clearly does tell the kernel to send 2 packets with its 2 `sendmsg()` syscalls:
The request in Wireshark is answered within 1 ms as expected.

So it seems that the kernel never sends the first packet.

(Side info:
Enabling the TCP mode of dig via `time dig +tcp ifconfig.me` changes the timeout to 1 second.
This suggests that the problem is with sending packets _in general_, not only UDP.
EDNS is generally used, but `+noedns` doesn't change the timeouts, no matter if `+tcp` is used or not.
)

I further discovered the problem is specific to the network interface I use.

My machine has 2 Ethernet ports:

* Realtek RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
* Intel Ethernet Connection (2) I218-V

The problem occurs _only_ on the Realtek port.

Details about the hardware from `lshw`:

```
        *-network
             description: Ethernet interface
             product: Ethernet Connection (2) I218-V
             vendor: Intel Corporation
             physical id: 19
             bus info: pci@0000:00:19.0
             logical name: enp0s25
             version: 00
             serial: d0:50:99:5c:cf:1c
             capacity: 1Gbit/s
             width: 32 bits
             clock: 33MHz
             capabilities: pm msi bus_master cap_list ethernet physical tp 10bt 10bt-fd 100bt 100bt-fd 1000bt-fd autonegotiation
             configuration: autonegotiation=on broadcast=yes driver=e1000e driverversion=3.2.6-k firmware=0.1-4 latency=0 link=no multicast=yes port=twisted pair
             resources: irq:42 memory:ef500000-ef51ffff memory:ef538000-ef538fff ioport:f040(size=32)
...
           *-network
                description: Ethernet interface
                product: RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
                vendor: Realtek Semiconductor Co., Ltd.
                physical id: 0
                bus info: pci@0000:03:00.0
                logical name: enp3s0
                version: 11
                serial: d0:50:99:5c:cf:1a
                size: 1Gbit/s
                capacity: 1Gbit/s
                width: 64 bits
                clock: 33MHz
                capabilities: pm msi pciexpress msix vpd bus_master cap_list ethernet physical tp mii 10bt 10bt-fd 100bt 100bt-fd 1000bt 1000bt-fd autonegotiation
                configuration: autonegotiation=on broadcast=yes driver=r8169 driverversion=2.3LK-NAPI duplex=full firmware=rtl8168g-2_0.0.1 02/06/13 ip=192.168.1.100 latency=0 link=yes multicast=yes port=MII speed=1Gbit/s
                resources: irq:37 ioport:d000(size=256) memory:ef400000-ef400fff memory:e2100000-e2103fff
```

User `longxia` from the `##linux` freenode IRC channel brought in the great suggestion to use `iptables` logging to see whether the packet missing in Wireshark is present there.


## Investigation with `iptables` logging facilities

All the below is for `UDP`. `enp3s0` is the Realtek Ethernet port.

I used `iptables -F && iptables -I OUTPUT 1 -j LOG && iptables -I OUTPUT 1 -j LOG`.

I observe during the hang:

```
Jan 27 23:24:16.210162 ares kernel: IN= OUT=enp3s0 SRC=192.168.1.100 DST=1.1.1.1 LEN=68 TOS=0x00 PREC=0x00 TTL=64 ID=57836 PROTO=UDP SPT=33554 DPT=53 LEN=48
# hang here
Jan 27 23:24:21.210106 ares kernel: IN= OUT=enp3s0 SRC=192.168.1.100 DST=1.1.1.1 LEN=68 TOS=0x00 PREC=0x00 TTL=64 ID=57843 PROTO=UDP SPT=33554 DPT=53 LEN=48
Jan 27 23:24:21.210645 ares kernel: IN=enp3s0 OUT= MAC=d0:50:99:5c:cf:1a:44:d9:e7:41:32:61:08:00 SRC=1.1.1.1 DST=192.168.1.100 LEN=132 TOS=0x00 PREC=0x00 TTL=54 ID=24125 DF PROTO=UDP SPT=53 DPT=33554 LEN=112
```

In the corresponding Wireshark capture below, we can see (with filter `dns.qry.name == "ifconfig.me"`) the two packets from after then hang.
But the first outgoing packet is not present!

```
2784  22:24:21.208712960  192.168.1.100 1.1.1.1 DNS 82  Standard query 0x8a93 A ifconfig.me OPT
2785  22:24:21.210606902  1.1.1.1 192.168.1.100 DNS 146 Standard query response 0x8a93 A ifconfig.me A 216.239.36.21 A 216.239.38.21 A 216.239.32.21 A 216.239.34.21 OPT
```

So I suspect that either:

* the packet gets lost in the kernel code path between the iptables layer and the layer that Wireshark attaches to
* the packet get sent, but forever reason doesn't show up in Wireshark (and the problem is the network not giving a response; unlikely given that the other network card works)
* the packet gets dropped by the kernel for some legitimate reason (e.g. hardware returning an error), but the kernel fails to report this error anywhere

Which of it could it be?
How should I investigate deeper?
