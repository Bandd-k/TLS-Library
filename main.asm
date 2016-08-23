;    main.asm - TLS client!
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

format binary as ""

__DEBUG__   = 1
__DEBUG_LEVEL__ = 1

BUFFERSIZE  = 4096
MAX_BITS    = 8192


use32

    db  'MENUET01'  ; signature
    dd  1   ; header version
    dd  start       ; entry point
    dd  i_end       ; initialized size
    dd  mem+4096    ; required memory
    dd  mem+4096    ; stack pointer
    dd  hostname    ; parameters
    dd  0   ; path

include 'macros.inc'
purge mov,add,sub
include 'proc32.inc'
include 'dll.inc'
include 'debug-fdo.inc'
include 'network.inc'
include 'transferdata.inc'

include 'mpint.inc'
include 'random.inc'
include 'hmac.inc'
include 'prf.inc'
include 'aes256.inc'
include 'aes256-ctr.inc'
include 'aes256-cbc.inc'
include 'sha256.inc'

start:
    mcall   68, 11      ; Init heap
    DEBUGF  1, "TLS: Loading libraries\n"
    stdcall dll.Load, @IMPORT
    test    eax, eax
    jnz exit

    DEBUGF  1, "TLS: Init PRNG\n"
    call    init_random

    DEBUGF  1, "TLS: Init Console\n"
    invoke  con_start, 1
    invoke  con_init, 80, 25, 80, 25, title

; Check for parameters
;       cmp     byte[hostname], 0
;       jne     resolve

main:
    invoke  con_cls
; Welcome user
    invoke  con_write_asciiz, str1

 prompt:
; write prompt
    invoke  con_write_asciiz, str2
; read string
    mov esi, hostname
    invoke  con_gets, esi, 256
; check for exit
    test    eax, eax
    jz  exit
    cmp byte[esi], 10
    jz  exit

resolve:
    mov [sockaddr1.port], 22 shl 8

; delete terminating '\n'
    mov esi, hostname
  @@:
    lodsb
    cmp al, ':'
    je  .do_port
    cmp al, 0x20
    ja  @r
    mov byte[esi-1], 0
    jmp .done

  .do_port:
    xor eax, eax
    xor ebx, ebx
    mov byte[esi-1], 0
  .portloop:
    lodsb
    cmp al, 0x20
    jbe .port_done
    sub al, '0'
    jb  hostname_error
    cmp al, 9
    ja  hostname_error
    lea ebx, [ebx*4 + ebx]
    shl ebx, 1
    add ebx, eax
    jmp .portloop

  .port_done:
    xchg    bl, bh
    mov [sockaddr1.port], bx

  .done:

; resolve name
    push    esp ; reserve stack place
    push    esp
    invoke  getaddrinfo, hostname, 0, 0
    pop esi
; test for error
    test    eax, eax
    jnz dns_error

    invoke  con_cls
    invoke  con_write_asciiz, str3
    invoke  con_write_asciiz, hostname

; write results
    invoke  con_write_asciiz, str8

; convert IP address to decimal notation
    mov eax, [esi+addrinfo.ai_addr]
    mov eax, [eax+sockaddr_in.sin_addr]
    mov [sockaddr1.ip], eax
    invoke  inet_ntoa, eax
; write result
    invoke  con_write_asciiz, eax
; free allocated memory
    invoke  freeaddrinfo, esi

    invoke  con_write_asciiz, str9

    mcall   40, EVM_STACK + EVM_KEY
    invoke  con_cls

; Create socket
    mcall   socket, AF_INET4, SOCK_STREAM, 0
    cmp eax, -1
    jz  socket_err
    mov [socketnum], eax

; Connect
    mcall   connect, [socketnum], sockaddr1, 18
    test    eax, eax
    jnz socket_err
    DEBUGF  1, "TLS: Socket Connected\n"
handshake:

;-----------------------------------------------------
; handshake description from HeavyThing library
; clienthello initial 3 bytes == 0x030316 (protocol = 3,3, 0x16 == 22 == handshake)
; byte #4 is the high order of our length
; byte #5 is the low order of our length
; bytes 6..length == our Handshake

; our Handshake looks like:
; byte #0 == 1 == client_hello
; byte #1 == high order of 24 bit length
; byte #2 == middle order
; byte #3 == low order

; then a ClientHello, which looks like:
; first two bytes == protocol version == 3,3
; next four bytes == 32 bit BIG ENDIAN ctime
; next 28 bytes == random bytes
; length-encoded up-to-32 byte session id is next (variable)
; length encoded _LIST_ of supported CipherSuites (each of which is 2 bytes) (length is up to 2^16-2, so we need two byte length encoding)
; length encoded list of compression methods, which are single byte, length is 2^8-1, so we need single byte length encoding
; end of record if no extensions are supported
; otherwise, a length encoded Extension list, length is 2 bytes.

; the initialclienthello goes out plaintext like, so we avoid having to deal with encrypting it
; so we can precompute our length as:
;   5 for the initial ContentType, Protocol Version, and 2 byte Length
; + 4 for the Handshake preface, (handshake type + 3 byte length)
; +34 for the protocol version, ctime, and 28 bytes of random in the ClientHello
; + 1 for the session id length encoding
; +?? for the sessionid length itself if nonzero
; + 2 byte length encoding for our supported CipherSuites
; +?? for the list of supported CipherSuites
; + 1 byte length for list of compression length, which will always be 1
; + 1 byte 0 for the null compression method
; --- stop there if no extension list
;  48 without our unknowns

; + tls_ciphersuite_size (which is in bytes)
; + our sessionid length (which might be zero)

;-----------------------------------------------------
    DEBUGF  1, "TLS: Handshake process starting\n"
    mov     dword [clienthello], 0x030316 ; protocol version, plus 0x16 (22) handshake (RFC says 3, 1 or 3,0 for record-layer clienthello)
    mov     eax,43+ciphersuites.length
    mov     byte [clienthello+3], ah
    mov     byte [clienthello+4], al
    mov     byte [clienthello+5], 1 ; client_hello
    sub     eax, 4
    mov     byte [clienthello+6], 0
    mov     byte [clienthello+7], ah
    mov     byte [clienthello+8], al
    mov     word [clienthello+9], 0x0303
    ; need to get gmt in big endian format into edx
    ;mov            dword[clienthello+11] , edx
    ; we use random time
    DEBUGF  1, "Generating RandomValues\n"
    mov     edi, clienthello+11
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    ;
    mov     esi,clienthello+11
    mov     ecx,32
    stdcall add_to_buffer_randoms
    ;
    mov     byte [clienthello+43], 0
    mov     byte [clienthello+44], 0
    mov     byte [clienthello+45], 2
    ; cipher suit!
    mov     byte [clienthello+46], 0x00
    ;0x2f-aes128
    ;0x35-aes256
    ;0x3D-aes256sha256
    mov     byte [clienthello+47], 0x3D
    mov     byte [clienthello+48], 1
    mov     byte [clienthello+49], 0
    mov     eax,50
    ;send client hello
    mcall   send, [socketnum], clienthello, 50, 0
    cmp     eax, -1
    je      socket_err


    mov     esi,clienthello+5
    mov     ecx,45
    stdcall add_to_buffer

    mcall   recv, [socketnum], serverAnswer, 79, 0 ;always constant size except error, add handler!
    cmp     eax, -1
    je      socket_err

    mov     esi,serverAnswer+5
    mov     ecx,74
    stdcall add_to_buffer

    ;add
    mov     esi,serverAnswer+11
    mov     ecx,32
    stdcall add_to_buffer_randoms
    ;
    ;check for version
    cmp     dword [serverAnswer],0x030316
    jne     serverhello_error
    cmp     byte [serverAnswer+5],2
    jne     serverhello_error

    ;save sessionid, it is the same size every time!
    mov     eax,dword [serverAnswer+44]
    DEBUGF  1, "TLS: recv sessionId %x\n",eax
    mov     dword [sessionid],eax
    mov     eax,dword [serverAnswer+48]
    mov     dword [sessionid+4],eax
    mov     eax,dword [serverAnswer+52]
    mov     dword [sessionid+8],eax
    mov     eax,dword [serverAnswer+56]
    mov     dword [sessionid+12],eax
    mov     eax,dword [serverAnswer+60]
    mov     dword [sessionid+16],eax
    mov     eax,dword [serverAnswer+64]
    mov     dword [sessionid+20],eax
    mov     eax,dword [serverAnswer+68]
    mov     dword [sessionid+24],eax
    mov     eax,dword [serverAnswer+72]
    mov     dword [sessionid+28],eax
    ;sessionid saved
    ; parse certificate message
    ; TODO rewrite into one message(It will be more correct)
    mcall   recv, [socketnum], serverAnswer, 9, 0
    cmp     eax, -1
    je      socket_err

    mov     esi,serverAnswer+5
    mov     ecx,4
    stdcall add_to_buffer

    mov     eax,dword[serverAnswer]

    cmp     byte [serverAnswer+5],0x0b
    jne     certificate_error
    mov     eax, dword[serverAnswer+6]
    bswap   eax
    shr     eax,8
    ;read certificate length
    mov     ecx,eax
    push    ecx
    DEBUGF  1, "TLS: lengh of certificate %d\n",eax
    push    eax
    add     eax,9;to   recieve serverhello done
    ;read certificate, site for reading der format http://www.lapo.it/asn1js/
    mcall   recv, [socketnum], serverAnswer, [eax], 0
    cmp     eax, -1
    je      socket_err

    pop     eax
    ;add certificate message to buffer
    mov     esi,serverAnswer
    mov     ecx,eax
    stdcall add_to_buffer
    
    ;check hello done
    add     eax,5
    cmp     dword[serverAnswer+eax],0x0000000e
    jne     serverhello_error


    ;add hello done to buffer
    mov     esi,serverAnswer
    add     esi,eax
    mov     ecx,4
    stdcall add_to_buffer


    ; start looking for public key from serverAnswer+3
    mov     ebx,3
    pop     ecx
    sub     ecx,6
    .loop1:
    ; find object 1.2.840.113549.1.1.1 in ASN corresponds public key in HEX (06092A864886F70D010101)

    cmp     dword[serverAnswer+ebx],0x0101010d
    je      .find
    inc     ebx
    dec     ecx
    cmp     ecx,0
    jne     .loop1
    ; not find public key go to error
    jmp     certificate_error

    .find:
    ; check for 864886F7
    cmp     dword[serverAnswer+ebx-4],0xf7864886
    jne     certificate_error
    ; pubK start from ebx+15, some hardcode! check it later! 4096 bit hardcode too.
    mov     ecx,0
    add     ebx,20
    ;plus 1, first 00 doesn't matter

    ; TODO delete this copying

    .loop2:
    mov     eax,dword[serverAnswer+ebx]
    mov     dword[RSApublicK+ecx+4],eax
    add     ecx,4
    add     ebx,4
    cmp     ecx,512
    jne     .loop2
    ;RSApublicK was saved
    add     ebx,2
    mov     eax,dword[serverAnswer+ebx]
    shr     eax,8



    ;serverhello_done recieve always 9
    ;DEBUGF  1, "TLS: Reciening server hello!!!\n"
    ;mcall   recv, [socketnum], clienthello, 5, 0
    ;cmp     eax, -1
    ;je     socket_err
    ;check
    ;cmp dword[clienthello+5],0x0000000e
    ;jne serverhello_error

    ;mov     esi,clienthello+5
    ;mov     ecx,4
    ;stdcall add_to_buffer

    DEBUGF  1, "TLS: Start calculating!!!\n"
    ; Exponent for Modexp! Small-Endian

    ; TODO exponent from certificate

    ;DEBUGF  1, "TLS: Exponent: \n"
    mov     dword[exponent],4
    mov     dword[exponent+4],65537
    stdcall mpint_length, exponent
    ;stdcall mpint_print, exponent


    ; Modulus for Modexp! Big-Endian
    mov     eax,512
    bswap   eax
    mov     dword[RSApublicK],eax
    ;DEBUGF  1, "TLS: PublicKey mod: \n"
    ; Convert Modulus to Small-Endian
    mov esi,RSApublicK
    mov edi,RSA_Modulus
    call    mpint_to_little_endian
    ;stdcall mpint_print, RSA_Modulus

    ;---------------TLS Client key Exchange Message--------------------
    ; 16 03 03 02 06 10 00 02 02 02 00
    ; ContentType (16), TLS version (03 03), Length 518 (02 06), Client key Exchange (10),Length 514 (00 02 02),Length 512 (02 00)
    ; Ecnrypted Premaster Key next.


    ;generate random Premaster key In Small-Endian
    mov     dword[premasterKey],52
    mov     edi,premasterKey+4
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    call    MBRandom
    stosd
    ; one more like padding
    call    MBRandom
    stosd
    ; set tls version
    mov     byte[premasterKey+50],0x03
    mov     byte[premasterKey+51],0x03
    mov     byte[premasterKey+52],0x00
    
    stdcall mpint_length, premasterKey
    ;stdcall mpint_print, premasterKey

    ; Calculate Modexp in Small-Endian
    stdcall mpint_modexp, buffer_buffer, premasterKey, exponent, RSA_Modulus
    stdcall mpint_length, buffer_buffer

    ;
    DEBUGF  1, "Encrypted premasterKey\n"
    stdcall mpint_print, buffer_buffer

    ; Convet Small-Endian Encrypted premasterKey to Big-Endian
    mov     esi,buffer_buffer
    mov     edi,clientKeyMessage+7
    call    mpint_to_big_endian


    mov dword[clientKeyMessage],0x02030316
    mov dword[clientKeyMessage+4],0x02001006
    mov word[clientKeyMessage+8],0x0202
    mov byte[clientKeyMessage+10],0x00



    mcall   send, [socketnum], clientKeyMessage, 523, 0
    cmp     eax, -1
    je      socket_err

    mov     esi,clientKeyMessage+5
    mov     ecx,518
    stdcall add_to_buffer


    ;---------------Change cipher spec message --------------------------
    ; 14 03 03 00 01 01
    mov     dword[clienthello], 0x00030314
    mov     word[clienthello+4],0x0101

    mcall   send, [socketnum], clienthello, 6, 0
    cmp     eax, -1
    je      socket_err


    ;Convert Premaster to Big-Endian
    mov     esi,premasterKey
    mov     edi,buffer_buffer
    call    mpint_to_big_endian




    ;
    DEBUGF  1, "Client Random\n"
    stdcall dump_256bit_hex, randoms_buffer

    DEBUGF  1, "Server Random\n"
    stdcall dump_256bit_hex, randoms_buffer+32


    ;remove later!!! delete zero

    cmp     byte[buffer_buffer+8],0x00
    je      .a
    mov     ebx,buffer_buffer+8
    jmp     .b
    .a:
    mov     ebx,buffer_buffer+9
    .b:



    DEBUGF  1, "premaster\n"
    stdcall print_numberNbytes,buffer_buffer+8,12
    mov     edx,48
    mov     eax,randoms_buffer
    mov     esi,64
    stdcall prf, master_str, master_str.length,masterKey
    DEBUGF  1, "MasterKey:\n"
    ; Sometimes appears bugs!
    stdcall dump_256bit_hex, masterKey


    ; change random places
    mov     esi, randoms_buffer
    mov     edi, randoms_buffer+64
    mov     ecx, 32/4
    rep     movsd

    ; calculate keys
    mov     ebx,masterKey
    mov     edx,48
    mov     eax,randoms_buffer+32
    mov     esi,64
    stdcall prf, keyExpansion_label, keyExpansion_label.length,session_keys
    DEBUGF  1, "TLS:Session Keys Were Saved\n"


; finished message = PRF(master_secret, finished_label, Hash(handshake_messages))[0..verify_data_length-1];
; Hash(handshake_messages) = SHA256(handshake_messages)
; SHA256(handshake_messages) = SHA256(handshake_message_buffer)

    call    sha256_init
    mov     esi,handshake_message_buffer
    mov     edx,dword[handshake_buffer_size]
    call    sha256_update
    mov     edi,buffer_buffer
    call    sha256_final
    DEBUGF  1, "TLS: Hash of Messages calculated\n"
    ; l(32) bytes in buffer_buffer are my SHA256(handshake_message_buffer)


    ;finished message header 16 03 03 00 40
    mov     dword[serverAnswer],0x00030316
    mov     byte[serverAnswer+4],0x50

    ;14 00 00 0C first bytes in encrypt part

    mov     dword[exponent],0x0c000014
    ; calculate verify data
    mov     ebx,masterKey
    mov     edx,48
    mov     eax, buffer_buffer
    mov     esi,l
    stdcall prf, finished_label, finished_label.length,exponent+4
    DEBUGF  1, "TLS: Verify Data calculated\n"
    ;now exponent has 4hdr+ 12 bytes verify data
    ;stdcall tls_send,[socketnum], exponent, 16,0


    ;----------send Finished message---------------------------------------------
    mov     dword[bufferptr],0x00030316
    mov     byte[bufferptr+4],0x50
    mov     esi, iv
    mov     edi, bufferptr+5
    mov     ecx, 16/4
    rep     movsd
    ;need to calculate MAC of buf
    ; Message authentication for FinishedMessage
    ;length 

    ;IT SHOULD BE OK

    mov     dword[msg],0
    mov     dword[msg+4],0
    ;type
    mov     byte[msg+8],0x16
    ;version
    mov     word[msg+9],0x0303
    ;length of message
    mov     byte[msg+11],0x00
    mov     byte[msg+12],0x10
    ;+info

    mov     ebx,session_keys.client_mac
    mov     edx,32
    stdcall hmac_setkey, tmp_buffer

    mov     eax,msg
    mov     edi,13
    stdcall hmac_hash,tmp_buffer

    mov     eax,exponent
    mov     edi,16
    stdcall hmac_add, tmp_buffer

    mov     edi,exponent
    add     edi,16
    push    edi
    stdcall hmac_final, tmp_buffer
    ;mac added
    pop     edi
    add     edi,32
    mov     dword[edi],0x0f0f0f0f
    add     edi,4
    mov     dword[edi],0x0f0f0f0f
    add     edi,4
    mov     dword[edi],0x0f0f0f0f
    add     edi,4
    mov     dword[edi],0x0f0f0f0f
    ;padding

    stdcall aes256_cbc_init, iv
    ; returns context, save it to ebx
    mov     ebx, eax
    stdcall aes256_set_encrypt_key, ebx, session_keys.client_enc
    DEBUGF 1,'CLient_enc Key\n'
    stdcall print_numberNbytes,session_keys.client_enc,8

    mov     edi,bufferptr+21
    mov     esi,exponent
    ;DEBUGF  1,'ToEncrypt\n'
    ;stdcall print_numberNbytes,exponent,16
    mov     ecx,4
    @@:
        push    ecx
        stdcall aes256_cbc_encrypt, ebx, esi, edi
        pop     ecx
        add     esi, 16
        add     edi, 16
        loop    @r

    
    DEBUGF  1,'Encrypt Succesful\n'
    mcall   send, [socketnum], bufferptr, 85, 0
    cmp     eax, -1
    je      socket_err




    ;-------------------------------------------------------------------
    ; Recieve Сhange cipher message
    mcall   recv, [socketnum], clienthello, 6, 0
    cmp     eax, -1
    je      socket_err
    cmp     byte[clienthello],0x14
    jne     socket_err; change error

    ;-------------------------------------------------------------------

    ; Recieve Finished message from server
    mcall   recv, [socketnum], buffer_buffer, 85, 0
    cmp     eax, -1
    je      socket_err

    ;TODO check Finished message from Server

    ;-------------------------------------------------------------------
    invoke  con_write_asciiz, str14
    stdcall tls_recieve, [socketnum], buffer_buffer, 117, 0
    mov     dword[buffer_buffer+61],0
    invoke  con_write_asciiz, buffer_buffer
    ;stdcall print_TextNbytes, buffer_buffer,64


exit:
    DEBUGF  1, "TLS: Exiting\n"
    mcall   close, [socketnum]
    mcall   -1

socket_err:
    DEBUGF  1, "TLS: socket error %d\n", ebx
    invoke  con_write_asciiz, str6
    jmp prompt

dns_error:
    DEBUGF  1, "TLS: DNS error %d\n", eax
    invoke  con_write_asciiz, str5
    jmp prompt


hostname_error:
    invoke  con_write_asciiz, str10
    jmp prompt

serverhello_error:
    invoke  con_write_asciiz, str12
    jmp prompt
certificate_error:
    invoke  con_write_asciiz, str13
    jmp prompt


; data
title   db  'Secure Shell',0
str1    db  'TLS client for KolibriOS',10,10,\
    'Please enter URL of TLS server (host:port)',10,10,0
str2    db  '> ',0
str3    db  'Connecting to ',0
str4    db  10,0
str5    db  'Name resolution failed.',10,10,0
str6    db  'A socket error occured.',10,10,0
str7    db  'A protocol error occured.',10,10,0
str8    db  ' (',0
str9    db  ')',10,0
str10   db  'Invalid hostname.',10,10,0
str11   db  10,'Remote host closed the connection.',10,10,0
str12   db  'Server Hello error.',10,10,0
str13   db  'certificate error.',10,10,0
str14   db  'TLS connected',10,10,0

master_str: 
    db 'master secret',0
    .length = $ - master_str - 1

finished_label: 
    db 'client finished',0
    .length = $ - finished_label - 1

keyExpansion_label: 
    db 'key expansion',0
    .length = $ - keyExpansion_label - 1




sockaddr1:
    dw AF_INET4
  .port dw 0
  .ip   dd 0
    rb 10

;2 x 32 byte keys and 2 x 32 bytes MAC keys
session_keys:
    .client_mac rb 32
    .server_mac rb 32
    .client_enc rb 32
    .server_enc rb 32

ciphersuites:
    db  0x00, 0x2f  ; TLS_RSA_WITH_AES_128_CBC_SHA          ; spec says we MUST support this one.
    .length = $ - ciphersuites




;function which add handshake messages to buffer
;input esi->message,ecx=size of message
proc add_to_buffer
    push eax
    push ecx
    mov edi,handshake_message_buffer
    add edi,[handshake_buffer_size]
    rep movsb
    pop ecx
    mov eax,[handshake_buffer_size]
    add eax,ecx
    mov [handshake_buffer_size],eax
    pop eax
    ret
endp

;function which add data to prf buffer
;input esi->message,ecx=size of message
proc add_to_buffer_randoms
    push ecx
    mov edi,randoms_buffer
    add edi,[randoms_buffer_size]
    rep movsb
    pop ecx
    mov eax,[randoms_buffer_size]
    add eax,ecx
    mov [randoms_buffer_size],eax
    ret
endp


;debug print functions

proc print_numberNbytes _ptr,n
        pushad
        mov     esi, [_ptr]
        mov     ecx, [n]
.next_dword:
        lodsd
        bswap eax
        DEBUGF  1,'%x',eax
        loop    .next_dword
        DEBUGF  1,'\n'
        popad
        ret
endp

proc print_TextNbytes _ptr,n
        pushad
        mov     esi, [_ptr]
        mov     ecx, [n]
.next_dword:
        lodsd
        bswap eax
        DEBUGF  1,'%s',eax
        loop    .next_dword
        DEBUGF  1,'\n'
        popad
        ret
endp



; import
include_debug_strings
align 4
@IMPORT:

library network, 'network.obj', \
    console, 'console.obj';, \
;        libcrash, 'libcrash.obj'

import  network, \
    getaddrinfo, 'getaddrinfo', \
    freeaddrinfo, 'freeaddrinfo', \
    inet_ntoa, 'inet_ntoa'

import  console, \
    con_start, 'START', \
    con_init, 'con_init', \
    con_write_asciiz, 'con_write_asciiz', \
    con_exit, 'con_exit', \
    con_gets, 'con_gets', \
    con_cls, 'con_cls', \
    con_getch2, 'con_getch2', \
    con_set_cursor_pos, 'con_set_cursor_pos', \
    con_write_string, 'con_write_string', \
    con_get_flags,  'con_get_flags'

IncludeUGlobals

i_end:

IncludeIGlobals
;variables
socketnum   dd ?
clienthello rb 64
sessionid   rb 32
hostname    rb 1024
serverAnswer rb 4048
RSApublicK rb MPINT_MAX_LEN+4 ; p*q
RSA_Modulus rb MPINT_MAX_LEN+4
exponent rb MPINT_MAX_LEN+4 ; e
buffer_buffer rb MPINT_MAX_LEN+4 ;
clientKeyMessage rb MPINT_MAX_LEN+4 ;
premasterKey rb MPINT_MAX_LEN+4;
mpint_tmp       rb MPINT_MAX_LEN+4
handshake_message_buffer rb 4048
handshake_buffer_size dd 0
randoms_buffer rb 4048
randoms_buffer_size dd 0
masterKey rb l*4


mem: