#!/usr/bin/env python2
#  -*- coding: utf-8 -*-
from pwn import *
import sys, os, traceback

# 输入为靶机 IP 和端口以及要验证的 flag
HOST = sys.argv[1]
PORT = sys.argv[2]
context(arch="amd64")

GLOBAL_TIMEOUT = 15

DEBUG = 0
if DEBUG:
    context(log_level="debug")
else:
    context(log_level="CRITICAL")

p = None

def add(idx, type, sz):
    p.sendlineafter(b">>", b'0') 
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(type).encode())
    p.sendlineafter(b":", str(sz).encode())
    p.recvuntil(b"[AUDIT] ")
    return int(p.recvline(), 16)

def free(idx):
    p.sendlineafter(b">>", b'1') 
    p.sendlineafter(b":", str(idx).encode())

def read(idx, sz):
    p.sendlineafter(b">>", b'2')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(sz).encode())
    p.recvuntil(b"[+] Data: ")
    return p.recvline().strip()

def write(idx, ctx):
    p.sendlineafter(b">>", b'3')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(len(ctx)).encode())
    p.sendafter(b":", ctx)

def seek(idx, whence, offset):
    p.sendlineafter(b">>", b'4')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(whence).encode())
    p.sendlineafter(b":", str(offset).encode())

#############################################################
def start_connection():
    global p
    try:
        if p:
            close_connection()
        p = remote(HOST, PORT, timeout=10)
    except:
        if DEBUG: 
            traceback.print_exc()
        FAIL("ConnectionFailure")
    
def close_connection():
    global p
    try:
        p.close()
        p = None
    except:
        pass

def timeout_handler(signum, frame):
    FAIL("timeout")

def FAIL(msg):
    if DEBUG:
        print("Fail: %s" %msg)
    print({"status": "down", "msg": "ERROR"})
    exit(-1)

def OK():
    print({"status": "up", "msg": "OK"})

#############################################################
def check_open_close():
    start_connection()
    
    for i in range(8):
        add(i, 0, 0x1f0)
    for i in range(1, 8):
        free(i)
    free(0)
    x = add(0, 0, 0x1f0)
    if x == 0x2a0:
        return 1
    FAIL("check_open_close")

def check_read_write_seek():
    start_connection()
    
    s = randoms(0x1f0).encode()
    add(0, 0, 0x200)
    write(0, s)
    seek(0, 0, 0x18)
    S = read(0, 0x1f0-0x18)
    if s[0x18:] == S:
        return 1
    FAIL("check_read_write")

def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(GLOBAL_TIMEOUT)
    
    if check_open_close() and check_read_write_seek():
        OK()
    
    close_connection()

# 主逻辑
if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        pass
    except:
        if DEBUG:
            traceback.print_exc()
        FAIL("UnknownException")
