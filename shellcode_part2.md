# Removing null opcodes (\x00)
Let's continue now, we will learn how to remove the null opcodes. Basic Linux/ASM knowledge is must.

Table of contents :
+ 0x01 Why we need to remove the nulls ?
+ 0x02 Exclusive OR (XOR)
+ 0x03 Removing null opcodes

# 0x01 Why we need to remove the nulls ?

This is our shellcode (exit() syscall) from the previous tutorial : 
```
\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80
```

You notice that there are some null opcodes (\x00). These nulls will cause our shellcode to fail when injected, because the null character is used to terminate strings. We need to find a way to change our nulls into non-null opcodes.

# 0x02 Exclusive OR (XOR)

XOR is a binary operation, it means "Exclusive OR". If both bits are equal we put 0 else we put 1.

For example :

```
1001 0101 0011 1101
0101 0100 1101 0101
-------------------
1100 0001 1110 1000
```

Let's test it out with python.

```python
>>> 0 ^ 0
0
>>> 1 ^ 1
0
>>> 1 ^ 0
1
```

This will be useful later, let's continue.

# 0x03 Removing null opcodes

To remove the null opcodes, we have to simply replace assembly instructions that create nulls with other instructions that do not.

Let's take a look into our 3 assembly instructions from the previous tutorial :

```asm
mov ebx,0          \xbb\x00\x00\x00\x00          
mov eax,1          \xb8\x01\x00\x00\x00                  
int 0x80           \xcd\x80  
```

The first two instructions are responsible for creating the nulls. As we said before, if both bits are equal we put 0 else we put 1. This means that if we use the XOR instruction on two operands that we know are equal, we can get the value of 0 without having to use a value of 0 in an instruction.  

This means that we'll not have a null opcode. Instead of using the mov instruction to set the value of 0 to EBX, let’s use the XOR instruction. So : 

```asm
mov ebx,0 
will be :
xor ebx,ebx 
```

Now you may be wondering why we have nulls in our second instruction `mov eax,1`. We didn’t put a zero value into the register, so why do we have nulls ? Well.. EAX is a 32-bit register & we're moving only one byte into the register but EAX register has space for 4. The rest of the register is going to be filled with nulls.


We can get around this problem if we remember that each 32-bit register is broken up into two 16-bit areas. The first 16-bit can be accessed with the AX register. The 16-bit AX register can be broken down further into the AL and AH registers. If you want only the first 8 bits, you can use the AL register. Our binary value of 1 will take up only 8 bits, so we can fit our value into this register and avoid EAX getting filled up with nulls.

Example : 

```
EAX: 12 34 56 78
AX: 56 78
AH: 56
AL: 78
```

So we change our instruction :

```asm
mov eax,1
to :
mov al,1
``` 

Let's test it out now. :)

```asm
Section  .text

	global _start

_start:

	xor ebx,ebx
	mov al,1
	int 0x80
```

We will use again the nasm assembler to create our object file, and then the GNU linker to link object file.

```bash
[root@pwn4magic]:~/Desktop# nasm -f elf exit_shellcode.asm
[root@pwn4magic]:~/Desktop# ld -m elf_i386 exit_shellcode.o -o exit_shellcode
```

Let's see now.

```bash
[root@pwn4magic]:~/Desktop# for i in `objdump -d exit_shellcode | tr '\t' ' ' | tr ' ' '\n' | egrep '^[0-9a-f]{2}$' ` ; do echo -n "\x$i" ; done
\x31\xdb\xb0\x01\xcd\x80
```

All our null opcodes have been removed, see you in the next tutorial. :)
