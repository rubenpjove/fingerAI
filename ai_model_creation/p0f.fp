; ==================
; TCP SYN signatures
; ==================

[tcp:request]

; -----
; Linux
; -----

label = s:unix:Linux:3.11 and newer
sig   = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,7:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:3.1-3.10
sig   = *:64:0:*:mss*10,4:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,5:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,6:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*10,7:mss,sok,ts,nop,ws:df,id+:0

; Fun fact: 2.6 with ws=7 seems to be really common for Amazon EC2, while 8 is
; common for Yahoo and Twitter. There seem to be some other (rare) uses, though,
; so not I'm not flagging these signatures in a special way.

label = s:unix:Linux:2.6.x
sig   = *:64:0:*:mss*4,6:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,7:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,8:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.4.x
sig   = *:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,1:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*4,2:mss,sok,ts,nop,ws:df,id+:0

; No real traffic seen for 2.2 & 2.0, signatures extrapolated from p0f2 data:

label = s:unix:Linux:2.2.x
sig   = *:64:0:*:mss*11,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*20,0:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*22,0:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.0
sig   = *:64:0:*:mss*12,0:mss::0
sig   = *:64:0:*:16384,0:mss::0

; Just to keep people testing locally happy (IPv4 & IPv6):

label = s:unix:Linux:3.x (loopback)
sig   = *:64:0:16396:mss*2,4:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:16376:mss*2,4:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.6.x (loopback)
sig   = *:64:0:16396:mss*2,2:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:16376:mss*2,2:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.4.x (loopback)
sig   = *:64:0:16396:mss*2,0:mss,sok,ts,nop,ws:df,id+:0

label = s:unix:Linux:2.2.x (loopback)
sig   = *:64:0:3884:mss*8,0:mss,sok,ts,nop,ws:df,id+:0

; Various distinctive flavors of Linux:

label = s:unix:Linux:2.6.x (Google crawler)
sig   = 4:64:0:1430:mss*4,6:mss,sok,ts,nop,ws::0

label = s:unix:Linux:(Android)
sig   = *:64:0:*:mss*44,1:mss,sok,ts,nop,ws:df,id+:0
sig   = *:64:0:*:mss*44,3:mss,sok,ts,nop,ws:df,id+:0

; Catch-all rules:

label = g:unix:Linux:3.x
sig   = *:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.4.x-2.6.x
sig   = *:64:0:*:mss*4,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x
sig   = *:64:0:*:*,*:mss,sok,ts,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x (no timestamps)
sig   = *:64:0:*:*,*:mss,nop,nop,sok,nop,ws:df,id+:0

label = g:unix:Linux:2.2.x-3.x (barebone)
sig   = *:64:0:*:*,0:mss:df,id+:0

; -------
; Windows
; -------

label = s:win:Windows:XP
sig   = *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,1:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,2:mss,nop,ws,nop,nop,sok:df,id+:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,2:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,2:mss,nop,ws,sok,ts:df,id+:0

; Robots with distinctive fingerprints:

label = s:win:Windows:7 (Websense crawler)
sig   = *:64:0:1380:mss*4,6:mss,nop,nop,ts,nop,ws:df,id+:0
sig   = *:64:0:1380:mss*4,7:mss,nop,nop,ts,nop,ws:df,id+:0

; Catch-all:

label = g:win:Windows:NT kernel 5.x
sig   = *:128:0:*:16384,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:16384,*:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,*:mss,nop,ws,nop,nop,sok:df,id+:0

label = g:win:Windows:NT kernel 6.x
sig   = *:128:0:*:8192,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,*:mss,nop,ws,nop,nop,sok:df,id+:0

label = g:win:Windows:NT kernel
sig   = *:128:0:*:*,*:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:*,*:mss,nop,ws,nop,nop,sok:df,id+:0

; ------
; Mac OS
; ------

label = s:unix:Mac OS X:10.x
sig   = *:64:0:*:65535,1:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,3:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:Mac OS X:10.9 or newer (sometimes iPhone or iPad)
sig   = *:64:0:*:65535,4:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

label = s:unix:iOS:iPhone or iPad
sig   = *:64:0:*:65535,2:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

; Catch-all rules:

label = g:unix:Mac OS X:
sig   = *:64:0:*:65535,*:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

; -------
; FreeBSD
; -------

label = s:unix:FreeBSD:9.x or newer
sig   = *:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0

label = s:unix:FreeBSD:8.x
sig   = *:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0

; Catch-all rules:

label = g:unix:FreeBSD:
sig   = *:64:0:*:65535,*:mss,nop,ws,sok,ts:df,id+:0

; -------
; OpenBSD
; -------

label = s:unix:OpenBSD:3.x
sig   = *:64:0:*:16384,0:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0

label = s:unix:OpenBSD:4.x-5.x
sig   = *:64:0:*:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0

; -------
; Solaris
; -------

label = s:unix:Solaris:8
sig   = *:64:0:*:32850,1:nop,ws,nop,nop,ts,nop,nop,sok,mss:df,id+:0

label = s:unix:Solaris:10
sig   = *:64:0:*:mss*34,0:mss,nop,ws,nop,nop,sok:df,id+:0

; -------
; OpenVMS
; -------

label = s:unix:OpenVMS:8.x
sig   = 4:128:0:1460:mtu*2,0:mss,nop,ws::0

label = s:unix:OpenVMS:7.x
sig   = 4:64:0:1460:61440,0:mss,nop,ws::0

; --------
; NeXTSTEP
; --------

label = s:other:NeXTSTEP:
sig   = 4:64:0:1024:mss*4,0:mss::0

; -----
; Tru64
; -----

label = s:unix:Tru64:4.x
sig   = 4:64:0:1460:32768,0:mss,nop,ws:df,id+:0


; -----------
; p0f-sendsyn
; -----------

; These are intentionally goofy, to avoid colliding with any sensible real-world
; stacks. Do not tag these signatures as userspace, unless you want p0f to hide
; the responses!

label = s:unix:p0f:sendsyn utility
sig   = *:192:0:1331:1337,0:mss,nop,eol+18::0
sig   = *:192:0:1331:1337,0:mss,ts,nop,eol+8::0
sig   = *:192:0:1331:1337,5:mss,ws,nop,eol+15::0
sig   = *:192:0:1331:1337,0:mss,sok,nop,eol+16::0
sig   = *:192:0:1331:1337,5:mss,ws,ts,nop,eol+5::0
sig   = *:192:0:1331:1337,0:mss,sok,ts,nop,eol+6::0
sig   = *:192:0:1331:1337,5:mss,ws,sok,nop,eol+13::0
sig   = *:192:0:1331:1337,5:mss,ws,sok,ts,nop,eol+3::0

; -------------
; Odds and ends
; -------------

label = s:other:Blackberry:
sig   = *:128:0:1452:65535,0:mss,nop,nop,sok,nop,nop,ts::0

label = s:other:Nintendo:3DS
sig   = *:64:0:1360:32768,0:mss,nop,nop,sok:df,id+:0

label = s:other:Nintendo:Wii
sig   = 4:64:0:1460:32768,0:mss,nop,nop,sok:df,id+:0

label = s:unix:BaiduSpider:
sig   = *:64:0:1460:mss*4,7:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0
sig   = *:64:0:1460:mss*4,2:mss,sok,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,nop,ws:df,id+:0

; ======================
; TCP SYN+ACK signatures
; ======================

[tcp:response]

; -----
; Linux
; -----

; The variation here is due to ws, sok, or ts being adaptively removed if the
; client initiating the connection doesn't support them. Use tools/p0f-sendsyn
; to get a full set of up to 8 signatures.


label = s:unix:Linux:3.x
sig   = *:64:0:*:mss*10,0:mss:df:0
sig   = *:64:0:*:mss*10,0:mss,sok,ts:df:0
sig   = *:64:0:*:mss*10,0:mss,nop,nop,ts:df:0
sig   = *:64:0:*:mss*10,0:mss,nop,nop,sok:df:0
sig   = *:64:0:*:mss*10,*:mss,nop,ws:df:0
sig   = *:64:0:*:mss*10,*:mss,sok,ts,nop,ws:df:0
sig   = *:64:0:*:mss*10,*:mss,nop,nop,ts,nop,ws:df:0
sig   = *:64:0:*:mss*10,*:mss,nop,nop,sok,nop,ws:df:0

label = s:unix:Linux:2.4-2.6
sig   = *:64:0:*:mss*4,0:mss:df:0
sig   = *:64:0:*:mss*4,0:mss,sok,ts:df:0
sig   = *:64:0:*:mss*4,0:mss,nop,nop,ts:df:0
sig   = *:64:0:*:mss*4,0:mss,nop,nop,sok:df:0

label = s:unix:Linux:2.4.x
sig   = *:64:0:*:mss*4,0:mss,nop,ws:df:0
sig   = *:64:0:*:mss*4,0:mss,sok,ts,nop,ws:df:0
sig   = *:64:0:*:mss*4,0:mss,nop,nop,ts,nop,ws:df:0
sig   = *:64:0:*:mss*4,0:mss,nop,nop,sok,nop,ws:df:0

label = s:unix:Linux:2.6.x
sig   = *:64:0:*:mss*4,*:mss,nop,ws:df:0
sig   = *:64:0:*:mss*4,*:mss,sok,ts,nop,ws:df:0
sig   = *:64:0:*:mss*4,*:mss,nop,nop,ts,nop,ws:df:0
sig   = *:64:0:*:mss*4,*:mss,nop,nop,sok,nop,ws:df:0

; -------
; Windows
; -------

label = s:win:Windows:XP
sig   = *:128:0:*:65535,0:mss:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,ws:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,nop,ts:df,id+,ts1-:0
sig   = *:128:0:*:65535,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:65535,0:mss,nop,ws,nop,nop,ts:df,id+,ts1-:0
sig   = *:128:0:*:65535,0:mss,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0
sig   = *:128:0:*:65535,0:mss,nop,ws,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0

sig   = *:128:0:*:16384,0:mss:df,id+:0
sig   = *:128:0:*:16384,0:mss,nop,ws:df,id+:0
sig   = *:128:0:*:16384,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:16384,0:mss,nop,nop,ts:df,id+,ts1-:0
sig   = *:128:0:*:16384,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:128:0:*:16384,0:mss,nop,ws,nop,nop,ts:df,id+,ts1-:0
sig   = *:128:0:*:16384,0:mss,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0
sig   = *:128:0:*:16384,0:mss,nop,ws,nop,nop,ts,nop,nop,sok:df,id+,ts1-:0

label = s:win:Windows:7 or 8
sig   = *:128:0:*:8192,0:mss:df,id+:0
sig   = *:128:0:*:8192,0:mss,sok,ts:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws:df,id+:0
sig   = *:128:0:*:8192,0:mss,nop,nop,ts:df,id+:0
sig   = *:128:0:*:8192,0:mss,nop,nop,sok:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws,sok,ts:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,ts:df,id+:0
sig   = *:128:0:*:8192,8:mss,nop,ws,nop,nop,sok:df,id+:0

; -------
; FreeBSD
; -------

label = s:unix:FreeBSD:9.x
sig   = *:64:0:*:65535,6:mss,nop,ws:df,id+:0
sig   = *:64:0:*:65535,6:mss,nop,ws,sok,ts:df,id+:0
sig   = *:64:0:*:65535,6:mss,nop,ws,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,6:mss,nop,ws,nop,nop,ts:df,id+:0

label = s:unix:FreeBSD:8.x
sig   = *:64:0:*:65535,3:mss,nop,ws:df,id+:0
sig   = *:64:0:*:65535,3:mss,nop,ws,sok,ts:df,id+:0
sig   = *:64:0:*:65535,3:mss,nop,ws,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,3:mss,nop,ws,nop,nop,ts:df,id+:0

label = s:unix:FreeBSD:8.x-9.x
sig   = *:64:0:*:65535,0:mss,sok,ts:df,id+:0
sig   = *:64:0:*:65535,0:mss,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0

; -------
; OpenBSD
; -------

label = s:unix:OpenBSD:5.x
sig   = *:64:0:1460:16384,0:mss,nop,nop,sok:df,id+:0
sig   = *:64:0:1460:16384,3:mss,nop,ws:df,id+:0
sig   = *:64:0:1460:16384,3:mss,nop,nop,sok,nop,ws:df,id+:0
sig   = *:64:0:1460:16384,0:mss,nop,nop,ts:df,id+:0
sig   = *:64:0:1460:16384,0:mss,nop,nop,sok,nop,nop,ts:df,id+:0
sig   = *:64:0:1460:16384,3:mss,nop,ws,nop,nop,ts:df,id+:0
sig   = *:64:0:1460:16384,3:mss,nop,nop,sok,nop,ws,nop,nop,ts:df,id+:0

; This one resembles Windows, but almost nobody will be seeing it:
; sig   = *:64:0:1460:16384,0:mss:df,id+:0

; --------
; Mac OS X
; --------

label = s:unix:Mac OS X:10.x
sig   = *:64:0:*:65535,0:mss,nop,ws:df,id+:0
sig   = *:64:0:*:65535,0:mss,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,nop,ts:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,ws,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,ws,nop,nop,ts:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,nop,ts,sok,eol+1:df,id+:0
sig   = *:64:0:*:65535,0:mss,nop,ws,nop,nop,ts,sok,eol+1:df,id+:0

; Ditto:
; sig   = *:64:0:*:65535,0:mss:df,id+:0

; -------
; Solaris
; -------

label = s:unix:Solaris:6
sig   = 4:255:0:*:mss*7,0:mss:df,id+:0
sig   = 4:255:0:*:mss*7,0:nop,ws,mss:df,id+:0
sig   = 4:255:0:*:mss*7,0:nop,nop,ts,mss:df,id+:0
sig   = 4:255:0:*:mss*7,0:nop,nop,ts,nop,ws,mss:df,id+:0

label = s:unix:Solaris:8
sig   = *:64:0:*:mss*19,0:mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,ws,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,nop,ts,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,nop,sok,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,nop,ts,nop,ws,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,ws,nop,nop,sok,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,nop,ts,nop,nop,sok,mss:df,id+:0
sig   = *:64:0:*:mss*19,0:nop,nop,ts,nop,ws,nop,nop,sok,mss:df,id+:0

label = s:unix:Solaris:10
sig   = *:64:0:*:mss*37,0:mss:df,id+:0
sig   = *:64:0:*:mss*37,0:mss,nop,ws:df,id+:0
sig   = *:64:0:*:mss*37,0:nop,nop,ts,mss:df,id+:0
sig   = *:64:0:*:mss*37,0:mss,nop,nop,sok:df,id+:0
sig   = *:64:0:*:mss*37,0:nop,nop,ts,mss,nop,ws:df,id+:0
sig   = *:64:0:*:mss*37,0:mss,nop,ws,nop,nop,sok:df,id+:0
sig   = *:64:0:*:mss*37,0:nop,nop,ts,mss,nop,nop,sok:df,id+:0
sig   = *:64:0:*:mss*37,0:nop,nop,ts,mss,nop,ws,nop,nop,sok:df,id+:0

; -----
; HP-UX
; -----

label = s:unix:HP-UX:11.x
sig   = *:64:0:*:32768,0:mss:df,id+:0
sig   = *:64:0:*:32768,0:mss,ws,nop:df,id+:0
sig   = *:64:0:*:32768,0:mss,nop,nop,ts:df,id+:0
sig   = *:64:0:*:32768,0:mss,nop,nop,sok:df,id+:0
sig   = *:64:0:*:32768,0:mss,ws,nop,nop,nop,ts:df,id+:0
sig   = *:64:0:*:32768,0:mss,nop,nop,sok,ws,nop:df,id+:0
sig   = *:64:0:*:32768,0:mss,nop,nop,sok,nop,nop,ts:df,id+:0
sig   = *:64:0:*:32768,0:mss,nop,nop,sok,ws,nop,nop,nop,ts:df,id+:0

; -------
; OpenVMS
; -------

label = s:other:OpenVMS:7.x
sig   = 4:64:0:1460:3993,0:mss::0
sig   = 4:64:0:1460:3993,0:mss,nop,ws::0

; -----
; Tru64
; -----

label = s:unix:Tru64:4.x
sig   = 4:64:0:1460:mss*25,0:mss,nop,ws:df,id+:0
sig   = 4:64:0:1460:mss*25,0:mss:df,id+:0