# Tiny Disassembler

This is a simple linear disassmbler written in python using the capstone library. 

```
terminal@terminal:~/tiny-disassembler$ ./linear.py 
Reading file: binary
Auto analyzing file...
Found 7 functions
Found 33 references
[0x4008d6]> 
```
Upon starting the script, it finds 7 functions, and 33 references to those functions. 


These functions can be listed using the `functions` command.

```
[0x4008d6]> functions
0x4008d6 main
0x4007e0 _start
0x400c64 _fini
0x400a70 hash
0x400c60 __libc_csu_fini
0x4006d0 _init
0x400bf0 __libc_csu_init
[0x4008d6]> 
```

Similar to radare2, the target instruction can be changed using the seek command.

```
[0x4008d6]> s _start
[0x4007e0]> s main
[0x4008d6]> 
```

Disassembly can be printed in a variety of forms.

```
[0x4008d6]> pdf

main:
	0x4008d6	push	rbp	
	0x4008d7	mov	rbp, rsp	
	0x4008da	sub	rsp, 0x50	
	0x4008de	mov	rax, qword ptr fs:[0x28]	
	0x4008e7	mov	qword ptr [rbp - 8], rax	
	0x4008eb	xor	eax, eax	
	0x4008ed	mov	edi, 0x400c78	
	0x4008f2	mov	eax, 0	
	0x4008f7	call	0x400740	
	0x4008fc	mov	rax, qword ptr [rip + 0x20178d]	
	0x400903	mov	rdi, rax	
	0x400906	call	0x4007b0	
	0x40090b	mov	rdx, qword ptr [rip + 0x20178e]	
	0x400912	lea	rax, [rbp - 0x30]	
	0x400916	mov	esi, 0x20	
	0x40091b	mov	rdi, rax	
	0x40091e	call	0x400780	
	0x400923	test	rax, rax	
	0x400926	jne	0x40093c	
	0x400928	mov	edi, 0x400c8a	
	0x40092d	call	0x400710	
	0x400932	mov	eax, 0	
	0x400937	jmp	0x400a5a	
	0x40093c	lea	rax, [rbp - 0x30]	# Referenced from: 0x4009260x400926
	0x400940	mov	rdi, rax	
	0x400943	call	0x400720	
	0x400948	mov	dword ptr [rbp - 0x40], eax	
	0x40094b	mov	eax, dword ptr [rbp - 0x40]	
	0x40094e	sub	eax, 1	
	0x400951	mov	eax, eax	
	0x400953	movzx	eax, byte ptr [rbp + rax - 0x30]	
	0x400958	cmp	al, 0xa	
	0x40095a	je	0x400970	
	0x40095c	mov	edi, 0x400c8a	
	0x400961	call	0x400710	
	0x400966	mov	eax, 0	
	0x40096b	jmp	0x400a5a	
	0x400970	mov	eax, dword ptr [rbp - 0x40]	# Referenced from: 0x40095a0x40095a
	0x400973	sub	eax, 1	
	0x400976	mov	eax, eax	
	0x400978	mov	byte ptr [rbp + rax - 0x30], 0	
	0x40097d	sub	dword ptr [rbp - 0x40], 1	
	0x400981	mov	eax, dword ptr [rbp - 0x40]	
	0x400984	shl	eax, 3	
	0x400987	add	eax, 1	
	0x40098a	mov	dword ptr [rbp - 0x3c], eax	
	0x40098d	mov	eax, dword ptr [rbp - 0x3c]	
	0x400990	mov	rdi, rax	
	0x400993	call	0x4007a0	
	0x400998	mov	qword ptr [rbp - 0x38], rax	
	0x40099c	cmp	qword ptr [rbp - 0x38], 0	
	0x4009a1	jne	0x4009ad	
	0x4009a3	mov	eax, 1	
	0x4009a8	jmp	0x400a5a	
	0x4009ad	mov	edx, dword ptr [rbp - 0x3c]	# Referenced from: 0x4009a10x4009a1
	0x4009b0	mov	rax, qword ptr [rbp - 0x38]	
	0x4009b4	mov	esi, 0	
	0x4009b9	mov	rdi, rax	
	0x4009bc	call	0x400750	
	0x4009c1	mov	dword ptr [rbp - 0x44], 0	
	0x4009c8	jmp	0x4009e9	
	0x4009ca	mov	eax, dword ptr [rbp - 0x44]	# Referenced from: 0x4009ef0x4009ef
	0x4009cd	cdqe		
	0x4009cf	movzx	eax, byte ptr [rbp + rax - 0x30]	
	0x4009d4	movsx	eax, al	
	0x4009d7	mov	rdx, qword ptr [rbp - 0x38]	
	0x4009db	mov	rsi, rdx	
	0x4009de	mov	edi, eax	
	0x4009e0	call	0x400a70	
	0x4009e5	add	dword ptr [rbp - 0x44], 1	
	0x4009e9	mov	eax, dword ptr [rbp - 0x44]	# Referenced from: 0x4009c80x4009c8
	0x4009ec	cmp	eax, dword ptr [rbp - 0x40]	
	0x4009ef	jb	0x4009ca	
	0x4009f1	mov	rax, qword ptr [rbp - 0x38]	
	0x4009f5	mov	esi, 0x400ca8	
	0x4009fa	mov	rdi, rax	
	0x4009fd	call	0x400790	
	0x400a02	test	eax, eax	
	0x400a04	je	0x400a2b	
	0x400a06	mov	edi, 0x400c8a	
	0x400a0b	call	0x400710	
	0x400a10	mov	rax, qword ptr [rbp - 0x38]	
	0x400a14	mov	rdi, rax	
	0x400a17	call	0x400700	
	0x400a1c	mov	qword ptr [rbp - 0x38], 0	
	0x400a24	mov	eax, 0	
	0x400a29	jmp	0x400a5a	
	0x400a2b	lea	rax, [rbp - 0x30]	# Referenced from: 0x400a040x400a04
	0x400a2f	mov	rsi, rax	
	0x400a32	mov	edi, 0x400d20	
	0x400a37	mov	eax, 0	
	0x400a3c	call	0x400740	
	0x400a41	mov	rax, qword ptr [rbp - 0x38]	
	0x400a45	mov	rdi, rax	
	0x400a48	call	0x400700	
	0x400a4d	mov	qword ptr [rbp - 0x38], 0	
	0x400a55	mov	eax, 0	
	0x400a5a	mov	rcx, qword ptr [rbp - 8]	# Referenced from: 0x400a290x400a29
	0x400a5e	xor	rcx, qword ptr fs:[0x28]	
	0x400a67	je	0x400a6e	
	0x400a69	call	0x400730	
	0x400a6e	leave		# Referenced from: 0x400a670x400a67
	0x400a6f	ret		
[0x4008d6]> 

```

It can also print a summary of a funtion calls using the `pdfs` command.


```
[0x4008d6]> pdfs
	0x4008f7	call	0x400740	
	0x400906	call	0x4007b0	
	0x40091e	call	0x400780	
	0x40092d	call	0x400710	
	0x400943	call	0x400720	
	0x400961	call	0x400710	
	0x400993	call	0x4007a0	
	0x4009bc	call	0x400750	
	0x4009e0	call	0x400a70	
	0x4009fd	call	0x400790	
	0x400a0b	call	0x400710	
	0x400a17	call	0x400700	
	0x400a3c	call	0x400740	
	0x400a48	call	0x400700	
	0x400a69	call	0x400730	
[0x4008d6]> 

```

Other commands can be found in the help menu.
