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

;include 'mpint.inc'
include 'random.inc'
;include 'aes256.inc'
;include 'aes256-ctr.inc'
;include 'aes256-cbc.inc'
;include 'sha256.inc'

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
    mov     byte [clienthello+43], 0
    mov     byte [clienthello+44], 0
    mov     byte [clienthello+45], 2
    mov     byte [clienthello+46], 0x00
    mov     byte [clienthello+47], 0x2f
    mov     byte [clienthello+48], 1
    mov     byte [clienthello+49], 0
    mov eax,50

    mcall   send, [socketnum], clienthello, 50, 0
    cmp eax, -1
    je	    socket_err
    mcall   recv, [socketnum], serverAnswer, 74, 0
    cmp eax, -1
    je	    socket_err
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

sockaddr1:
    dw AF_INET4
  .port dw 0
  .ip	dd 0
    rb 10

ciphersuites:
	db  0x00, 0x2f	; TLS_RSA_WITH_AES_128_CBC_SHA          ; spec says we MUST support this one.
    .length = $ - ciphersuites


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

mem: