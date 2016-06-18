;    hmac.inc - HMAC: Keyed-Hashing for Message Authentication
;
;    Copyright (C) 2016 Denis Karpenko
;
;    This program is free software: you can redistribute it and/or modify
;    it under the terms of the GNU General Public License as published by
;    the Free Software Foundation, either version 3 of the License, or
;    (at your option) any later version.
;
;    This program is distributed in the hope that it will be useful,
;    but WITHOUT ANY WARRANTY; without even the implied warranty of
;    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;    GNU General Public License for more details.
;
;    You should have received a copy of the GNU General Public License
;    along with this program.  If not, see <http://www.gnu.org/licenses/>.

b = 64 ; block_size
l = 32 ; output length for SHA256
hmac_tmp	rb 4096 ; rewrite to cut memory!!! USING SHA256 upgrade
second_block rb 4096
third		rb 4096

input db 'hial',0
secret db 'okok',0
check:
	mov ebx,secret
	mov edx,4
	mov eax,input
	mov edi,4
	call hmac





hmac:
; input ebx->key,edx=key_length, eax->text, edi=text_length
	push edi
	push eax
	call sha256_init
	call calculate_new_key

	;second_block->newKey,hmac_tmp->newKey
	call xor_ipad
	call xor_opad
	stdcall dump_512bit_hex, second_block
	stdcall dump_512bit_hex, hmac_tmp

	;int 3
	;second_block->(newKey xor opad),hmac_tmp->(newKey xor ipad)
	mov esi,hmac_tmp
	mov edx,b
	call sha256_update
	pop eax
	pop edi
	mov edx,edi
	mov esi,eax
	call sha256_update
	mov edi,hmac_tmp
	call sha256_final
	; hmac_tmp=H((Key xor ipad)||text)
	DEBUGF	1,"H((Key xor ipad)||text) = \n"
	stdcall dump_256bit_hex, hmac_tmp
	call sha256_init
	mov  edx,b
	mov  esi,second_block
	call sha256_update
	mov  edx,l
	mov  esi,hmac_tmp
	call sha256_update
	mov  edi,hmac_tmp
	call sha256_final
	DEBUGF	1, "answer\n"
	stdcall dump_256bit_hex, hmac_tmp
	ret

calculate_new_key:
; input ebx = key, edx=key_length
; output eax = newKey with 64 length
	push ebx
	push edx
	.start:
	call	sha256_init
	;copy key to hmac_tmp
	mov		edi,hmac_tmp
	mov		ecx,0
	.loop:
	mov		eax,[ebx+ecx]
	add	ecx,4
	stosd
	cmp	ecx,edx ; key divisable by 4
	jne		.loop
	cmp	edx,b
	je		.equal
	jnl	.more
	.less:
	; fill zeros from right
	mov		eax,0
	.loop2:
	add	ecx,4
	stosd
	cmp	ecx,b
	jne		.loop2
	jmp	.return
	.more:
	mov	esi,ebx
	call	sha256_update
	mov edi,hmac_tmp
	call	sha256_final ;edi - answer, 32 bytes
	mov	ebx,hmac_tmp
	mov	edx,l
	jmp	.start
	.equal:
	jmp	.return

	.return:
	;copy new key to second buffer!!
	mov	ebx,hmac_tmp
	mov		edi,second_block
	mov		ecx,0
	.loop7:
	mov		eax,[ebx+ecx]
	add	ecx,4
	stosd
	cmp	ecx,b
	jne		.loop7
	;DEBUGF	1,"newKey\n"
	;call print_tmp
	pop edx
	pop ebx
	ret

concat_withtext:
;ebx=text, edx = text_length
	mov edi, hmac_tmp+b
	mov ecx,0
    .loop5:
    mov eax,[ebx+ecx]
    stosb
    add ecx,1
    cmp ecx,edx
    jne .loop5
    ret

concat_s0withH:
;esi=text, edx = text_length
	mov edi, second_block+b
	mov ecx,0
    .loop6:
    mov eax,[esi+ecx]
    stosb
    add ecx,1
    cmp ecx,edx
    jne .loop6
    ret






xor_ipad:
;modify hmac_tmp
;ipad = 0x36
	push ecx
	push eax
	mov ecx,0
	.loop3:
	mov eax,dword[hmac_tmp+ecx]
	xor eax,0x36363636
	mov dword[hmac_tmp+ecx],eax
	add ecx,4
	cmp	ecx,b
	jne		.loop3
	pop eax
	pop ecx
	ret


xor_opad:
;modify second_block
;opad = 0x5c
	push ecx
	push eax
	mov ecx,0
	.loop4:
	mov eax,dword[second_block+ecx]
	xor eax,0x5c5c5c5c
	mov dword[second_block+ecx],eax
	add ecx,4
	cmp	ecx,b
	jne		.loop4
	pop eax
	pop ecx
	ret

print_tmp:
	DEBUGF	1,"tmp:\n"
	mov eax,dword[hmac_tmp]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+4]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+8]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+12]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+16]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+20]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+24]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[hmac_tmp+28]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+32]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+36]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+40]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+44]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+48]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[hmac_tmp+52]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+56]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+60]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+64]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+68]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+72]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	ret
print_last:
	DEBUGF	1,"tmp:\n"
	mov eax,dword[hmac_tmp]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+4]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+8]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+12]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+16]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+20]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+24]
	DEBUGF	1,"%x",eax
	mov eax,dword[hmac_tmp+28]
	DEBUGF	1,"%x",eax
	ret
print_third:
	DEBUGF	1,"tmp:\n"
	mov eax,dword[third]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+4]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+8]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+12]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+16]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+20]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+24]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[third+28]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+32]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+36]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+40]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+44]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+48]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[third+52]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+56]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+60]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+64]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+68]
	DEBUGF	1,"%x",eax
	mov eax,dword[third+72]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	ret
print_second_block:
	DEBUGF	1,"tmp:\n"
	mov eax,dword[second_block]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+4]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+8]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+12]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+16]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+20]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+24]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[second_block+28]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+32]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+36]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+40]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+44]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+48]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	mov eax,dword[second_block+52]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+56]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+60]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+64]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+68]
	DEBUGF	1,"%x",eax
	mov eax,dword[second_block+72]
	DEBUGF	1,"%x",eax
	DEBUGF	1,"\n"
	ret



proc dump_256bit_hex _ptr
	pushad

	mov	esi, [_ptr]
	mov	ecx, 8
  .next_dword:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.next_dword
	DEBUGF	1,'\n'

	popad
	ret
endp
proc dump_512bit_hex _ptr
	pushad

	mov	esi, [_ptr]
	mov	ecx, 8
  .next_dword:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.next_dword
	DEBUGF	1,'\n'

	mov ecx,8
	.nxt:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.nxt
	DEBUGF	1,'\n'


	popad
	ret
endp
proc dump_768bit_hex _ptr
	pushad

	mov	esi, [_ptr]
	mov	ecx, 8
  .next_dword:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.next_dword
	DEBUGF	1,'\n'

	mov ecx,8
	.nxt:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.nxt
	DEBUGF	1,'\n'

	mov ecx,8
	.nxt2:
	lodsd
	bswap	eax
	DEBUGF	1,'%x',eax
	loop	.nxt2
	DEBUGF	1,'\n'


	popad
	ret
endp
