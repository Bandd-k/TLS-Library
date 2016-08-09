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

;; -------example----------
; input      db 'hial',0
; inp2       db 'al',0
; secret     db 'okok',0
; answer     rb 50
; buffer     rb 2*b
; check:
;     mov    ebx,secret
;     mov    edx,4
;     stdcall hmac_setkey,buffer
;     mov    eax,input
;     mov    edi,4
;     stdcall   hmac_hash,buffer
;     mov    edi,answer
;     stdcall   hmac_final,buffer
;     stdcall   dump_256bit_hex, answer
;     ret



b = 64 ; block_size
l = 32 ; output length for SHA256

struct hmac_context
        ipad    rb      b
        opad    rb      b
ends
; HOWTO use
; call hmac_setkey-> call hmac_hash->call hmac_final
; All functions need one shared _tmpbuffer with 64(2*b) bytes!
; Each function needs the same buffer with other functions!

; function to set new key
proc hmac_setkey _tmpbuffer
; ebx->key,edx=key_lengths
; _tmpbuffer should be at least 64(2*b) bytes!
        pushad
        stdcall calculate_new_key,[_tmpbuffer]
; opad->newKey,ipad->newKey
        mov     eax,[_tmpbuffer]
        lea     edi,[eax+hmac_context.ipad]
        mov     edx,0x36363636
        call    make_xor
        lea     edi,[eax+hmac_context.opad]
        mov     edx,0x5c5c5c5c
        call    make_xor
        stdcall dump_512bit_hex, edi
        popad
        ret
endp

; function to add first data
proc hmac_hash _tmpbuffer
; eax->text, edi=text_length
; _tmpbuffer should be at least 64(2*b) bytes!
        push    eax
        push    edi
        call    sha256_init
        mov     eax,[_tmpbuffer]
        lea     esi,[eax+hmac_context.ipad]
        mov     edx,b
        call    sha256_update
        pop     edi
        pop     eax
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        ret
endp
; function to add more data to HMAC
proc hmac_add _tmpbuffer
; eax->text, edi=text_length
        pushad
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        popad
        ret
endp

; finalize data
proc hmac_final _tmpbuffer
; input edi->answerbuffer
; _tmpbuffer should be at least 64(2*b) bytes!
        pushad
; push answer on stack
        sub esp,b
        mov     edi,esp
        call    sha256_final
; ipad=H((Key xor ipad)||text)
        call    sha256_init
        mov     edx,b
        mov     eax,[_tmpbuffer]
        lea     esi,[eax+hmac_context.opad]
        call    sha256_update
        mov     edx,l
        mov     esi,esp
        add     esp,b
; take answer from stack
        call    sha256_update
        popad
        call    sha256_final
        ret
endp

proc calculate_new_key _tmpbuffer
; input ebx = key, edx=key_length
; _tmpbuffer should be at least 64(2*b) bytes!
        push    ebx
        push    edx
        cmp     edx,b
        jnl     .hash_it
; Key is smaller then or equal to key size,
; copy key to ipad
        mov     esi,ebx
        mov     eax,[_tmpbuffer]
        lea     edi,[eax+hmac_context.ipad]
        mov     ecx, edx
        rep     movsb
        mov     ecx, b
        sub     ecx, edx
.add_zeros:
; Given key is smaller then key size,
; append zeros to the key
        xor     al, al
        rep     stosb
        jmp     .return

.hash_it:
        call    sha256_init
        mov     esi,ebx
        call    sha256_update
        mov     eax, [_tmpbuffer]
        lea     edi, [eax+hmac_context.ipad]
        call    sha256_final
; edi - answer, 32 bytes
        add     edi,l
        mov     ecx,b-l
        jmp     .add_zeros
.return:
; copy new key to second buffer!!
  ; copy generated key to second buffer
        mov     eax, [_tmpbuffer]
        lea     esi, [eax+hmac_context.ipad]
        lea     edi,[eax+hmac_context.opad]
        mov     ecx, b/4
        rep movsd
        pop     edx
        pop     ebx
        ret
endp

make_xor:
; input edi->firstoperand, edx=xorvalue
; change edi
        mov     ecx,0
        @@:
        xor     dword[edi+ecx],edx
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

