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
;prf_output      rb l*3
tmp_buffer      rb 2*b
; input ebx->secret,edx=secret_length, eax->seed, esi=seed_length
proc prf _label, label_size, _output
        push    eax
        push    esi
        push    eax
        push    esi
        push    eax
        push    esi

        push    eax
        push    esi
        stdcall    hmac_setkey, tmp_buffer
;firstly calculate As

        ;label_addition
        mov eax,[_label]
        mov edi,[label_size]
        stdcall hmac_hash,tmp_buffer


        pop     edi
        pop     eax
        stdcall    hmac_add, tmp_buffer
        mov     edi,A_1
        stdcall    hmac_final, tmp_buffer
; A_1 was calculated
        mov     eax,A_1
        mov     edi,l
        stdcall    hmac_hash, tmp_buffer
        mov     edi,A_2
        stdcall    hmac_final, tmp_buffer
; A_2 was calculated
        mov     eax,A_2
        mov     edi,l
        stdcall    hmac_hash, tmp_buffer
        mov     edi,A_3
        stdcall    hmac_final, tmp_buffer
; A_3 was calculated
        mov     eax,A_1
        mov     edi,l
        stdcall    hmac_hash, tmp_buffer

        ;label_addition
        mov eax,[_label]
        mov edi,[label_size]
        stdcall hmac_add,tmp_buffer

        pop     edi
        pop     eax
        stdcall    hmac_add, tmp_buffer
        mov     edi,[_output]
        stdcall    hmac_final, tmp_buffer

; prf_output= HMAC_hash(secret, A(1) + seed)
        mov     eax,A_2
        mov     edi,l
        stdcall    hmac_hash, tmp_buffer

        ;label_addition
        mov eax,[_label]
        mov edi,[label_size]
        stdcall hmac_add,tmp_buffer

        pop     edi
        pop     eax
        stdcall    hmac_add, tmp_buffer
        mov     edi,[_output]
        add     edi,l
        stdcall    hmac_final, tmp_buffer
; prf_output= HMAC_hash(secret, A(1) + seed)+HMAC_hash(secret, A(2) + seed)
        mov     eax,A_3
        mov     edi,l
        stdcall    hmac_hash, tmp_buffer

        ;label_addition
        mov eax,[_label]
        mov edi,[label_size]
        stdcall hmac_add,tmp_buffer

        pop     edi
        pop     eax
        stdcall    hmac_add, tmp_buffer
        mov     edi,[_output]
        add     edi,2*l
        stdcall    hmac_final, tmp_buffer
        ;DEBUGF  1,'PRF:\n'
        ;stdcall dump_512bit_hex, [_output]
        ret
endp
        ; prf_output= HMAC_hash(secret, A(1) + seed)+HMAC_hash(secret, A(2) + seed)+HMAC_hash(secret, A(3) + seed)
        ; prf should be 80, so we discard last 16 bytes