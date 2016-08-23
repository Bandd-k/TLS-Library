;    TLS-library functions.
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




;input data,size of data
bufferptr       rb 4096
msg             rb 4096
padding         rb 1
proc tls_send sock, buf, size, flags
; message structure header 00030317+ size in big endian(2 bytes) + IV(16 bytes) +Encrypted(buf+mac(32bytes)+padding)
; copy iv to start of message
    mov dword[bufferptr],0x00030317
    ; bufferptr + 4 should be whole size!!
    ;calculate padding size;
    mov eax,[size]
    xor edx,edx ;clear the destinations for outputs. 
    mov ecx,16
    div ecx
    mov eax,16
    sub eax,edx
    mov byte[padding],0x0f
    cmp eax,0
    je  .ok
    dec eax
    mov byte[padding],al
    .ok:

    ;copy IV 
	mov     esi, iv
    mov     edi, bufferptr+5
    mov     ecx, 16/4
    rep movsd
    ;need to calculate MAC of buf
    ; Message authentication
    ;length 
    ;IT SHOULD BE OK
    mov dword[msg],0
    mov eax,dword[seq_number]
    bswap eax
    mov dword[msg+4],eax
    ;type
    mov byte[msg+8],0x17
    ;version
    mov word[msg+9],0x0303
    ;length of message (2 bytes)
    mov eax,[size] 
    xchg    al, ah
    mov word[msg+11],ax
    ;+info

    mov ebx,session_keys.client_mac
    mov edx,32
    stdcall    hmac_setkey, tmp_buffer

    mov eax,msg
    mov edi,13
    stdcall hmac_hash,tmp_buffer

    mov eax,[buf]
    mov edi,[size]
    stdcall hmac_add, tmp_buffer

    mov edi,[buf]
    add edi,[size]
    push edi
    stdcall hmac_final, tmp_buffer
    ;mac added

    pop edi
    add edi,32
    ;fill padding in edi there


    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, session_keys.client_enc
    DEBUGF 1,'CLient_enc Key\n'
    stdcall print_numberNbytes,session_keys.client_enc,8

    mov edi,bufferptr+21
    mov esi,[buf]
    DEBUGF 1,'ToEncrypt\n'
    stdcall print_numberNbytes,[buf],16

    ;mov ecx,[padding]

    mov ecx,4
    @@:
        push    ecx
        stdcall aes256_cbc_encrypt, ebx, esi, edi
        pop     ecx
        add     esi, 16
        add     edi, 16
        sub     ecx,16
    cmp ecx,0
    jne    @r

    ;to send
    DEBUGF 1,'ToSend\n'
    stdcall print_numberNbytes,bufferptr,22
    
    DEBUGF 1,'Encrypted Succesful\n'
    mcall   send, [socketnum], bufferptr, 85, 0
    cmp     eax, -1
    je      socket_err
    ret


endp

;TODO rewrite SIZE should be decrypted info without IV and such stuff
;TODO INPUT not socket! TLS Structure
proc tls_recieve sock, buf, size, flags

    mcall   recv, [socketnum], bufferptr, [size], 0
    cmp     eax, -1
    je      socket_err


    ;IV at bufferptr +5 (5 bytes header)
    stdcall aes256_cbc_init, bufferptr+5
    ; returns context, save it to ebx
    mov     ebx, eax
    mov eax,[size]
    ;size minus header
    sub eax,5
    ; minus IV size
    sub eax,16
    mov esi,bufferptr+21
    mov edi,[buf]
    push eax
    stdcall aes256_set_decrypt_key, ebx, session_keys.server_enc
    pop ecx

    @@:
    push    ecx
        stdcall aes256_cbc_decrypt, ebx, esi, edi
        pop     ecx
        add     esi, 16
        add     edi, 16
        sub     ecx,16
    cmp ecx,0
    jne    @r
    ret
endp


mac_buffer rb 2*b
proc mac, content
    mov ebx, key
    mov edx, 32
    stdcall    hmac_setkey, mac_buffer

    mov eax,[_label]
    mov edi,[label_size]
    stdcall hmac_hash,tmp_buffer

    ret
endp



seq_number dd 0

key db      0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,\
            0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,\
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
tx_buffer rb 4096
iv      db      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,\
                0x0c,0x0d,0x0e,0x0f