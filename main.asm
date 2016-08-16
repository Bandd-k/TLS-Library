;    main.asm - tls for KolibriOS



format binary as ""

__DEBUG__   = 1
__DEBUG_LEVEL__ = 1

BUFFERSIZE  = 4096
MAX_BITS    = 8192

DH_PRIVATE_KEY_SIZE = 256

use32

    db	'MENUET01'  ; signature
    dd	1	; header version
    dd	start	    ; entry point
    dd	i_end	    ; initialized size
    dd	mem+4096    ; required memory
    dd	mem+4096    ; stack pointer
    dd	hostname    ; parameters
    dd	0	; path

include 'macros.inc'
purge mov,add,sub
include 'proc32.inc'
include 'dll.inc'
include 'debug-fdo.inc'
include 'network.inc'
;include 'libcrash.inc'

;include 'mcodes.inc'
;include 'ssh_transport.inc'
;include 'dh_gex.inc'

include 'mpint.inc'
include 'random.inc'
include 'hmac.inc'
include 'prf.inc'
include 'aes256.inc'
include 'aes256-ctr.inc'
include 'aes256-cbc.inc'
include 'sha256.inc'

start:
	mcall	68, 11	    ; Init heap
	DEBUGF	1, "TLS: Loading libraries\n"
	stdcall dll.Load, @IMPORT
	test	eax, eax
	jnz exit

	DEBUGF	1, "TLS: Init PRNG\n"
    call    init_random

	DEBUGF	1, "TLS: Init Console\n"
	invoke	con_start, 1
	invoke	con_init, 80, 25, 80, 25, title

; Check for parameters
;       cmp     byte[hostname], 0
;       jne     resolve

main:
	invoke	con_cls
; Welcome user
	invoke	con_write_asciiz, str1

prompt:
; write prompt
    invoke  con_write_asciiz, str2
; read string
    mov esi, hostname
    invoke  con_gets, esi, 256
; check for exit
    test    eax, eax
    jz	exit
    cmp byte[esi], 10
    jz	exit

resolve:
    mov [sockaddr1.port], 22 shl 8

; delete terminating '\n'
    mov esi, hostname
  @@:
    lodsb
    cmp al, ':'
    je	.do_port
    cmp al, 0x20
    ja	@r
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
    jb	hostname_error
    cmp al, 9
    ja	hostname_error
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
    jz	socket_err
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
    mov eax,43+ciphersuites.length
    mov     byte [clienthello+3], ah
    mov     byte [clienthello+4], al
    mov     byte [clienthello+5], 1 ; client_hello
    sub eax, 4
    mov     byte [clienthello+6], 0
    mov     byte [clienthello+7], ah
    mov     byte [clienthello+8], al
    mov     word [clienthello+9], 0x0303
    ; need to get gmt in big endian format into edx
    ;mov            dword[clienthello+11] , edx
    ; we use random time
    DEBUGF  1, "Generating RandomValues\n"
    mov edi, clienthello+11
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
    stdcall add_to_buffer_master
    ;
    mov     byte [clienthello+43], 0
    mov     byte [clienthello+44], 0
    mov     byte [clienthello+45], 2
    ; cipher suit!
    mov     byte [clienthello+46], 0x00
    ;0x2f-aes128
    ;0x35-aes256
    mov     byte [clienthello+47], 0x35
    mov     byte [clienthello+48], 1
    mov     byte [clienthello+49], 0
    mov     eax,50
    ;send client hello
    mcall   send, [socketnum], clienthello, 50, 0
    cmp     eax, -1
    je	    socket_err

    mov     esi,clienthello
    mov     ecx,50
    stdcall add_to_buffer

    mcall   recv, [socketnum], serverAnswer, 79, 0 ;always constant size except erorr, add handler!
    cmp     eax, -1
    je	    socket_err

    mov     esi,serverAnswer
    mov     ecx,79
    stdcall add_to_buffer

    ;add
    mov     esi,serverAnswer+11
    mov     ecx,32
    stdcall add_to_buffer_master
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
    mcall   recv, [socketnum], serverAnswer, 9, 0
    cmp     eax, -1
    je	    socket_err

    mov     esi,serverAnswer
    mov     ecx,9
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
    push eax
    ;read certificate, site for reading der format http://www.lapo.it/asn1js/
    mcall   recv, [socketnum], serverAnswer, [eax], 0
    cmp     eax, -1
    je	    socket_err

    pop eax
    mov     esi,serverAnswer
    mov     ecx,eax
    stdcall add_to_buffer

    ; start looking for public key from serverAnswer+3
    mov     ebx,3
    pop     ecx
    sub     ecx,6
    .loop1:
    ; find object 1.2.840.113549.1.1.1 in ASN corresponds public key in HEX (06092A864886F70D010101)

    cmp     dword[serverAnswer+ebx],0x0101010d
    je	    .find
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

    ;--------------------- Jeffrey -------------------------------;
    ;------------------Look here please --------------------------;

    DEBUGF  1, "TLS: Start calculating!!!\n"
    ; Exponent for Modexp! Small-Endian
    DEBUGF  1, "TLS: Exponent: \n"
    mov     dword[exponent],4
    mov     dword[exponent+4],65537
    stdcall mpint_length, exponent
    stdcall mpint_print, exponent


    ; Modulus for Modexp! Big-Endian
    mov     eax,512
    bswap   eax
    mov     dword[RSApublicK],eax
    DEBUGF  1, "TLS: PublicKey mod: \n"
    ; Convert Modulus to Small-Endian
    mov esi,RSApublicK
    mov edi,RSA_Modulus
    call    mpint_to_little_endian
    stdcall mpint_length,RSA_Modulus
    stdcall mpint_print, RSA_Modulus

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
    mov     byte[premasterKey+50],0x03
    mov     byte[premasterKey+51],0x03
    mov     byte[premasterKey+52],0x00
    
    stdcall mpint_length, premasterKey
    stdcall mpint_print, premasterKey

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
    je	    socket_err

    mov     esi,clientKeyMessage
    mov     ecx,523
    stdcall add_to_buffer


    ;---------------Change cipher spec message --------------------------
    ; 14 03 03 00 01 01
    mov dword[clienthello], 0x00030314
    mov word[clienthello+4],0x0101

    mcall   send, [socketnum], clienthello, 6, 0
    cmp     eax, -1
    je	    socket_err


    ;Convert Premaster to Big-Endian
    mov     esi,premasterKey
    mov     edi,buffer_buffer
    call    mpint_to_big_endian




    ;
    DEBUGF  1, "Client Random\n"
    stdcall dump_256bit_hex, master_seed

    DEBUGF  1, "Server Random\n"
    stdcall dump_256bit_hex, master_seed+32

    mov ebx,buffer_buffer+8
    DEBUGF  1, "premaster\n"
    stdcall print_number48bytes,buffer_buffer+8
    mov edx,48
    mov eax,master_seed
    mov esi,64
    stdcall prf, master_str, master_str.length,masterKey
    DEBUGF  1, "MasterKey:\n"
    stdcall dump_256bit_hex, masterKey









exit:
	DEBUGF	1, "TLS: Exiting\n"
	mcall	close, [socketnum]
	mcall	-1

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
title	db  'Secure Shell',0
str1	db  'TLS client for KolibriOS',10,10,\
	'Please enter URL of TLS server (host:port)',10,10,0
str2	db  '> ',0
str3	db  'Connecting to ',0
str4	db  10,0
str5	db  'Name resolution failed.',10,10,0
str6	db  'A socket error occured.',10,10,0
str7	db  'A protocol error occured.',10,10,0
str8	db  ' (',0
str9	db  ')',10,0
str10	db  'Invalid hostname.',10,10,0
str11	db  10,'Remote host closed the connection.',10,10,0
str12	db  'Server Hello error.',10,10,0
str13	db  'certificate error.',10,10,0

master_str: 
	db 'master secret',0
	.length = $ - master_str - 1

finished_label: 
	db 'client finished',0
	.length = $ - finished_label - 1


sockaddr1:
    dw AF_INET4
  .port dw 0
  .ip	dd 0
    rb 10

ciphersuites:
	db  0x00, 0x2f	; TLS_RSA_WITH_AES_128_CBC_SHA          ; spec says we MUST support this one.
    .length = $ - ciphersuites




;function which add handshake messages to buffer
;input esi->message,ecx=size of message
proc add_to_buffer
	push ecx
	mov edi,handshake_message_buffer
	add edi,[handshake_buffer_size]
	rep movsb
	pop ecx
	mov eax,[handshake_buffer_size]
	add eax,ecx
	mov [handshake_buffer_size],eax
	ret
endp

;function which add data to prf buffer
;input esi->message,ecx=size of message
proc add_to_buffer_master
	push ecx
	mov edi,master_seed
	add edi,[master_seed_size]
	rep movsb
	pop ecx
	mov eax,[master_seed_size]
	add eax,ecx
	mov [master_seed_size],eax
	ret
endp

proc print_number48bytes _ptr
        pushad
        mov     esi, [_ptr]
        mov     ecx, 12
.next_dword:
        lodsd
        bswap eax
        DEBUGF  1,'%x',eax
        loop    .next_dword
        DEBUGF  1,'\n'
        popad
        ret
endp

proc print_number512bytes _ptr
        pushad
        mov     esi, [_ptr]
        mov     ecx, 128
.next_dword:
        lodsd
        bswap eax
        DEBUGF  1,'%x',eax
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

import	network, \
    getaddrinfo, 'getaddrinfo', \
    freeaddrinfo, 'freeaddrinfo', \
    inet_ntoa, 'inet_ntoa'

import	console, \
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
socketnum   dd ?
clienthello rb 64
sessionid   rb 32
hostname    rb 1024
serverAnswer rb 4048
RSApublicK rb MPINT_MAX_LEN+4 ; p*q
RSA_Modulus rb MPINT_MAX_LEN+4
second	rb 10
exponent rb MPINT_MAX_LEN+4 ; e
buffer_buffer rb MPINT_MAX_LEN+4 ;
clientKeyMessage rb MPINT_MAX_LEN+4 ;
premasterKey rb MPINT_MAX_LEN+4;
mpint_tmp       rb MPINT_MAX_LEN+4
handshake_message_buffer rb 4048
handshake_buffer_size dd 0
master_seed rb 4048
master_seed_size dd 0
masterKey rb l*3


mem: