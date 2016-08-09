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
    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, key



endp


proc tls_recieve sock, buf, size, flags
    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, key



endp


iv      db      0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,\
                0x0c,0x0d,0x0e,0x0f