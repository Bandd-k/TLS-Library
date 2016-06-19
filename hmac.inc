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

;example:
;input      db 'hial',0
;secret     db 'okok',0
;    mov    ebx,secret
;    mov    edx,4
;    mov    eax,input
;    mov    edi,4
;    call   hmac

b = 64 ; block_size
l = 32 ; output length for SHA256
tmp1            rb 4096
tmp2            rb 4096

hmac:
; input ebx->key,edx=key_length, eax->text, edi=text_length
; output ebx->answer
        push    edi
        push    eax
        call    sha256_init
        call    calculate_new_key
; tmp2->newKey,tmp1->newKey
        mov     edi,tmp1
        mov     edx,0x36363636
        call    make_xor
        mov     edi,tmp2
        mov     edx,0x5c5c5c5c
        call    make_xor
        stdcall dump_512bit_hex, tmp2
        stdcall dump_512bit_hex, tmp1

; tmp2->(newKey xor opad),tmp1->(newKey xor ipad)
        mov     esi,tmp1
        mov     edx,b
        call    sha256_update
        pop     eax
        pop     edi
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        mov     edi,tmp1
        call    sha256_final
; tmp1=H((Key xor ipad)||text)
        DEBUGF  1,"H((Key xor ipad)||text) = \n"
        stdcall dump_256bit_hex, tmp1
        call    sha256_init
        mov     edx,b
        mov     esi,tmp2
        call    sha256_update
        mov     edx,l
        mov     esi,tmp1
        call    sha256_update
        mov     edi,tmp1
        call    sha256_final
        DEBUGF  1, "answer\n"
        stdcall dump_256bit_hex, tmp1
        mov     ebx, tmp1
        ret

calculate_new_key:
; input ebx = key, edx=key_length
; output eax -> newKey with 64 length
        push    ebx
        push    edx
    .start:
        call    sha256_init
; copy key to tmp1
        mov     edi,tmp1
        mov     ecx,0
    .loop1:
        mov     eax,[ebx+ecx]
        add     ecx,1
        stosb
        cmp     ecx,edx
        jne     .loop1
        cmp     edx,b
        je      .equal
        jnl     .more
    .less:
; fill zeros from right
        mov     eax,0
    .loop2:
        add     ecx,1
        stosb
        cmp     ecx,b
        jne     .loop2
        jmp     .return
    .more:
        mov     esi,ebx
        call    sha256_update
        mov     edi,tmp1
        call    sha256_final
; edi - answer, 32 bytes
        mov     ebx,tmp1
        mov     edx,l
        jmp     .start
    .equal:
        jmp     .return
    .return:
; copy new key to second buffer!!
        mov     ebx,tmp1
        mov     edi,tmp2
        mov     ecx,0
    .loop3:
        mov     eax,[ebx+ecx]
        add     ecx,4
        stosd
        cmp     ecx,b
        jne     .loop3
        pop     edx
        pop     ebx
        ret

make_xor:
; input edi->firstoperand, edx=xorvalue
; change edi
        mov     ecx,0
    .loop:
        mov     eax,dword[edi+ecx]
        xor     eax,edx
        stosd
        add     ecx,4
        cmp     ecx,b
        jne     .loop
        ret


proc dump_256bit_hex _ptr
        pushad
        mov     esi, [_ptr]
        mov     ecx, 8
    .next_dword:
        lodsd
        bswap   eax
        DEBUGF  1,'%x',eax
        loop    .next_dword
        DEBUGF  1,'\n'
        popad
        ret
endp


proc dump_512bit_hex _ptr
        pushad
        mov     esi, [_ptr]
        mov     ecx, 8
    .next_dword:
        lodsd
        bswap   eax
        DEBUGF  1,'%x',eax
        loop    .next_dword
        DEBUGF  1,'\n'
        mov     ecx,8
    .nxt:
        lodsd
        bswap   eax
        DEBUGF  1,'%x',eax
        loop    .nxt
        DEBUGF  1,'\n'
        popad
        ret
endp
