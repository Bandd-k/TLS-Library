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

; -------example----------
; input      db 'hial',0
; inp2       db 'al',0
; secret     db 'okok',0
; answer     rb 50
; check:
;     mov    ebx,secret
;     mov    edx,4
;     call hmac_setkey
;     mov    eax,input
;     mov    edi,4
;     call   hmac_hash
;     mov    edi,answer
;     call   hmac_final
;     stdcall dump_256bit_hex, answer
;     ret

b = 64 ; block_size
l = 32 ; output length for SHA256
ipad    rb      b
opad    rb      b
temporaryData rb b

; HOWTO use
; call hmac_setkey-> call hmac_hash->call hmac_final

; function to set new key
hmac_setkey:
; ebx->key,edx=key_lengths
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

; function to add first data
hmac_hash:
; eax->text, edi=text_length
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
; function to add more data to HMAC
hmac_add:
; eax->text, edi=text_length
        pushad
        mov     edx,edi
        mov     esi,eax
        call    sha256_update
        popad
        ret

; finalize data
hmac_final:
; input edi->answerbuffer
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
        cmp     edx,b
        jnl     .hash_it
; Key is smaller then or equal to key size,
; copy key to ipad
        mov     esi,ebx
        mov     edi, ipad
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
        mov     edi,ipad
        call    sha256_final
; edi - answer, 32 bytes
        add     edi,l
        mov     ecx,b-l
        jmp     .add_zeros
.return:
; copy new key to second buffer!!
  ; copy generated key to second buffer
        mov     esi, ipad
        mov     edi, opad
        mov     ecx, b/4
        rep movsd
        pop     edx
        pop     ebx
        ret

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

