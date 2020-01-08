# Introduction To Shellcoding

Im reading at the time a great book [The Shellcoder's Handbook: Discovering and Exploiting Security Holes](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X). I want to take my binary exploitation skills a step farther. Im writing this tutorial because i want to understand better what im reading/doing like a guy said "you think you understand something until you try to teach it" & because i want to use this as my personal "cheat sheet" if you get me. Let's begin!

Table of contents :
+ 0x01 What is shellcode ?
+ 0x02 System Calls + ASM Analysis
+ 0x03 Writing Shellcode for exit() Syscall

# 0x01 What is shellcode ?

Shellcode is our payload, lot of `\x**` characters together. For example `\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80` is a piece of shellcode which when executed will spawn a shell. If the vulnerable binary is SETUID will give us a root shell! 

Shellcode generally written in an assembler & translated into hexadecimal opcodes.

You cannot inject shellcode written from a high-level language like (python,ruby etc), because there are thing that will prevent shellcode from executing cleanly & give us shell for example. This is what makes writing shellcode hard.

Hope you now understand what shellcode really is. Let's move on.

# 0x02 System Calls + ASM Analysis



