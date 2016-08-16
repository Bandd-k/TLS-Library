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

proc tls_send sock, buf, size, flags
locals
        bufferptr       rb 4096
endl
; copy iv to start of message
	mov     esi, iv
    mov     edi, bufferptr
    mov     ecx, 16/4
    rep movsd

    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, key

    ; Message authentication




endp


proc tls_recieve sock, buf, size, flags
    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, key



endp

mac_buffer rb 2*b
proc mac, content,
    mov ebx, key
    mov edx, 32
    stdcall    hmac_setkey, mac_buffer

    mov eax,[_label]
    mov edi,[label_size]
    stdcall hmac_hash,tmp_buffer





endp


version db 0x0303; tls 1.2 version
type db 0x14 ; FInishedMessage


key db      0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,\
            0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,\
            0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4
tx_buffer rb 4096
iv      db      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,\
                0x0c,0x0d,0x0e,0x0f