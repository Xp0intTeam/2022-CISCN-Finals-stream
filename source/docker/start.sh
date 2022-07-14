#!/bin/sh
exec /usr/sbin/xinetd -dontfork -f /etc/xinetd.d/ctf.xinetd
