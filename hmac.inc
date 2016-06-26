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

; WARNING!
; USING SHA256 and HMAC in one time can cause errors

;example:
;input      db 'hial',0
;inp2       db 'al',0
;secret     db 'okok',0
;answer     rb 50
; check:
; ;    mov    ebx,secret
; ;    mov    edx,4
; ;    mov    eax,input
; ;    mov    edi,4
; ;    call   hmac


b = 64 ; block_size
l = 32 ; output length for SHA256
ipad    rb      4096
opad    rb      4096
temporaryData rb 100


hmac:
; first version of  HMAC (1 function)
; input ebx->key,edx=key_length, eax->text, edi=text_length
; output ebx->answer
        push    edi
        push    eax
        call    sha256_init
        call    calculate_new_key
; opad->newKey,ipad->newKey
        mov     edi,ipad
        mov     edx,0x36363636
        call    make_xor
        mov     edi,opad
        mov     edx,0x5c5c5c5c
        call    make_xor
        stdcall dump_512bit_hex, opad
        stdcall dump_512bit_hex, ipad

; opad->(newKey xor opad),ipad->(newKey xor ipad)
        mov     esi,ipad
        mov     edx,b
        call    sha256_update
        pop     eax
        pop     edi
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        mov     edi,ipad
        call    sha256_final
; ipad=H((Key xor ipad)||text)
        DEBUGF  1,"H((Key xor ipad)||text) = \n"
        stdcall dump_256bit_hex, ipad
        call    sha256_init
        mov     edx,b
        mov     esi,opad
        call    sha256_update
        mov     edx,l
        mov     esi,ipad
        call    sha256_update
        mov     edi,ipad
        call    sha256_final
        DEBUGF  1, "answer\n"
        stdcall dump_256bit_hex, ipad
        mov     ebx, ipad
        ret

; Second option (call hmac_setkey-> call hmac_hash->call hmac final_data)
; function to set new key input 
; ebx->key,edx=key_length
hmac_setkey:
        pushad
        call    calculate_new_key
; opad->newKey,ipad->newKey
        mov     edi,ipad
        mov     edx,0x36363636
        call    make_xor
        mov     edi,opad
        mov     edx,0x5c5c5c5c
        call    make_xor
        stdcall dump_512bit_hex, opad
        stdcall dump_512bit_hex, ipad
        popad
        ret

; eax->text, edi=text_length
hmac_hash:
        push    eax
        push    edi
        call    sha256_init
        mov     esi,ipad
        mov     edx,b
        call    sha256_update
        pop     edi
        pop     eax
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        ret
; eax->text, edi=text_length
; add more data to HMAC
hmac_add:
        pushad
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        popad
        ret

;input edi->answerbuffer
hmac_final:
        pushad
        mov     edi,temporaryData
        call    sha256_final
; ipad=H((Key xor ipad)||text)
        DEBUGF  1,"H((Key xor ipad)||text) = \n"
        stdcall dump_256bit_hex, temporaryData
        call    sha256_init
        mov     edx,b
        mov     esi,opad
        call    sha256_update
        mov     edx,l
        mov     esi,temporaryData
        call    sha256_update
        popad
        call    sha256_final
        ret


calculate_new_key:
; input ebx = key, edx=key_length
; output eax -> newKey with 64 length
        push    ebx
        push    edx
.start:
        call    sha256_init
; copy key to ipad
        mov     edi,ipad
        mov     ecx,0
@@:
        mov     eax,[ebx+ecx]
        add     ecx,1
        stosb
        cmp     ecx,edx
        jne     @b
        cmp     edx,b
        je      .equal
        jnl     .more
.less:
; fill zeros from right
        mov     eax,0
@@:
        add     ecx,1
        stosb
        cmp     ecx,b
        jne     @b
        jmp     .return
.more:
        mov     esi,ebx
        call    sha256_update
        mov     edi,ipad
        call    sha256_final
; edi - answer, 32 bytes
        mov     ebx,ipad
        mov     edx,l
        jmp     .start
.equal:
        jmp     .return
.return:
; copy new key to second buffer!!
        mov     ebx,ipad
        mov     edi,opad
        mov     ecx,0
@@:
        mov     eax,[ebx+ecx]
        add     ecx,4
        stosd
        cmp     ecx,b
        jne     @b
        pop     edx
        pop     ebx
        ret

make_xor:
; input edi->firstoperand, edx=xorvalue
; change edi
        mov     ecx,0
        @@:
        mov     eax,dword[edi+ecx]
        xor     eax,edx
        stosd
        add     ecx,4
        cmp     ecx,b
        jne     @b
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

