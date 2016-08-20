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
proc tls_send sock, buf, size, flags
; copy iv to start of message
    mov dword[bufferptr],0x00030316
    mov byte[bufferptr+4],0x50
	mov     esi, iv
    mov     edi, bufferptr+5
    mov     ecx, 16/4
    rep movsd
    ;need to calculate MAC of buf
    ; Message authentication for FinishedMessage
    ;length 
    ;IT SHOULD BE OK
    mov dword[msg],0
    mov dword[msg+4],0
    ;type
    mov byte[msg+8],0x16
    ;version
    mov word[msg+9],0x0303
    ;length of message
    mov byte[msg+11],0x00
    mov byte[msg+12],0x10
    ;+info

    mov ebx,session_keys.client_mac
    mov edx,32
    stdcall    hmac_setkey, tmp_buffer

    mov eax,msg
    mov edi,13
    stdcall hmac_hash,tmp_buffer

    mov eax,[buf]
    mov edi,16
    stdcall hmac_add, tmp_buffer

    mov edi,[buf]
    add edi,16
    push edi
    stdcall hmac_final, tmp_buffer
    ;mac added

    pop edi
    add edi,32
    mov dword[edi],0x0f0f0f0f
    add edi,4
    mov dword[edi],0x0f0f0f0f
    add edi,4
    mov dword[edi],0x0f0f0f0f
    add edi,4
    mov dword[edi],0x0f0f0f0f
    ;padding

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
    mov ecx,4
    @@:
        push    ecx
        stdcall aes256_cbc_encrypt, ebx, esi, edi
        pop     ecx
        add     esi, 16
        add     edi, 16
        loop    @r

    ;to send
    DEBUGF 1,'ToSend\n'
    stdcall print_numberNbytes,bufferptr,22
    
    DEBUGF 1,'Encrypted Succesful\n'
    mcall   send, [socketnum], bufferptr, 85, 0
    cmp     eax, -1
    je      socket_err
    ret


endp


proc tls_recieve sock, buf, size, flags
    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, key


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


version db 0x03,0x03; tls 1.2 version
type db 0x14 ; FInishedMessage


key db      0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,\
            0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,\
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
tx_buffer rb 4096
iv      db      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,\
                0x0c,0x0d,0x0e,0x0f