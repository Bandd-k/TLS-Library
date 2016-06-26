;    prf.inc - Pseudo Random function based on HMAC
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

;PRF(secret, seed) = HMAC_hash(secret, A(1) + seed) +
;                             HMAC_hash(secret, A(2) + seed) +
;                             HMAC_hash(secret, A(3) + seed)
;A() is defined as:
;
;      A(0) = seed
;      A(i) = HMAC_hash(secret, A(i-1))

A_1     rb      l
A_2     rb      l
A_3     rb      l
prf_output      rb l*3
; input ebx->secret,edx=secret_length, eax->seed, esi=seed_length
prf:
        push    eax
        push    esi
        push    eax
        push    esi
        push    eax
        push    esi

        push    eax
        call    hmac_setkey
;firstly calculate As
        mov     edi,esi
        pop     eax
        call    hmac_hash
        mov     edi,A_1
        call    hmac_final
; A_1 was calculated
        mov     eax,A_1
        mov     edi,l
        call    hmac_hash
        mov     edi,A_2
        call    hmac_final
; A_2 was calculated
        mov     eax,A_2
        mov     edi,l
        call    hmac_hash
        mov     edi,A_3
        call    hmac_final
; A_3 was calculated
        DEBUGF  1,'As calculated\n'
        mov     eax,A_1
        mov     edi,l
        call    hmac_hash
        pop     edi
        pop     eax
        call    hmac_add
        mov     edi,prf_output
        call    hmac_final
; prf_output= HMAC_hash(secret, A(1) + seed)
        mov     eax,A_2
        mov     edi,l
        call    hmac_hash
        pop     edi
        pop     eax
        call    hmac_add
        mov     edi,prf_output
        add     edi,l
        call    hmac_final
; prf_output= HMAC_hash(secret, A(1) + seed)+HMAC_hash(secret, A(2) + seed)
        mov     eax,A_3
        mov     edi,l
        call    hmac_hash
        pop     edi
        pop     eax
        call    hmac_add
        mov     edi,prf_output
        add     edi,2*l
        call    hmac_final
        DEBUGF  1,'PRF:\n'
        stdcall dump_512bit_hex, prf_output
        ret
        ; prf_output= HMAC_hash(secret, A(1) + seed)+HMAC_hash(secret, A(2) + seed)+HMAC_hash(secret, A(3) + seed)
        ; prf should be 80, so we discard last 16 bytes