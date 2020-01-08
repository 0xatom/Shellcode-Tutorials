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

Things are getting a bit harder here. Basic ASM/Linux knowledge is must.

One way to control a program is to force it to make a system call(syscall). Syscalls are really powerful functions, that allow you to access operating system functions like : input, ouput, exit, execute. Syscalls allow you to directly access the kernel, which gives you access to low-level functions like reading and writing files. Syscalls are ways by which user mode interacts with the kernel mode.

You can get the list of the syscalls by executing : 
```bash
[root@pwn4magic]:~/Desktop# man syscalls
```

![syscalls](https://i.ibb.co/G0TBk65/syscalls.png)

There are 2 methods of executing a syscall in linux. You can use the C libc (library of standard functions) which works indirectly or execute directly with assembly.

The int 0x80 instruction call syscalls in linux. When int 0x80 is executed by a user mode program, CPU switches into kernel mode and executes the syscall.

The process :
1. The syscall number is loaded into EAX. (EAX Register stores the return value of a function)
2. Syscall function arguments are placed in other registers.
3. The instruction int 0x80 is executed.
4. The CPU switches to kernel mode.
5. The syscall function is executed.

Each syscall can have a maximum of six arguments, which placed into EBX, ECX, EDX, ESI, EDI, and EPB.

Now let's make a syscall in C & then disassemble the binary. So we can see the assembly instructions. The most basic syscall is exit() (cause normal process termination).

```C
#include <stdio.h>

main()
{
	exit(0);
}
```

Let's compile it now.

```bash
[root@pwn4magic]:~/Desktop# gcc -static -m32 -w exit.c -o exit
[root@pwn4magic]:~/Desktop# file exit
exit: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, BuildID[sha1]=db2e8edbbe52d0a8cf0c58777df3f8bccbd39990, for GNU/Linux 3.2.0, not stripped
[root@pwn4magic]:~/Desktop# ./exit 
```

I used the `-m32` option because i use 64bit OS. Now let's disassemble the binary.

```asm
[root@pwn4magic]:~/Desktop# gdb -q exit
Reading symbols from exit...
(No debugging symbols found in exit)
gdb-peda$ disassemble _exit
Dump of assembler code for function _exit:
   0x0806bf3a <+0>:	mov    ebx,DWORD PTR [esp+0x4]
   0x0806bf3e <+4>:	mov    eax,0xfc
   0x0806bf43 <+9>:	call   DWORD PTR gs:0x10
   0x0806bf4a <+16>:	mov    eax,0x1
   0x0806bf4f <+21>:	int    0x80
   0x0806bf51 <+23>:	hlt    
End of assembler dump.
gdb-peda$ 
```

We have 2 syscalls. The number of the syscall to be called is stored in EAX

```asm
0x0806bf3e <+4>:	mov    eax,0xfc
0x0806bf4a <+16>:	mov    eax,0x1
```

`0xfc = 252 = sys_exit_group`
`0x1  = 1   = 	sys_exit`

Then we have an instruction that loads the argument for our exit syscall into EBX.

```asm
0x0806bf3a <+0>:	mov    ebx,DWORD PTR [esp+0x4]
```

In the end, we have the the ```0x0806bf4f <+21>:	int    0x80``` instrunction, which switch the CPU to kernel mode.

# 0x03 Writing Shellcode for exit() Syscall
