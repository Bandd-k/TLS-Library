# Google Summer of Code 2016

**Project**: [Development of TLS library for KolibriOS](https://summerofcode.withgoogle.com/projects/#5973545913942016)  
**Organization**: [JBoss Community](http://kolibrios.org)  
**Mentors**: Jeffrey Amelynck,Pathoswithin  
**Student**: [Denis Karpenko](https://github.com/bandd-k)  
**University**: [National Research University Higher School of Economics](https://www.hse.ru/en/) 
### Abstract
There is a [tiny TLS 1.2 Library](https://github.com/Bandd-k/TLS-Library). It supports only one cipher suit TLS_RSA_WITH_AES_256_CBC_SHA256(strong cipher). According to specification it is enough for correct TLS connection.
### What was actually done

* [HMAC based on SHA256](https://tools.ietf.org/html/rfc2104). Well tested! Stable
* [Pseudo-random function based on HMAC](https://tools.ietf.org/html/rfc5246#section-5). Well tested! Stable
* [RSA exhange algortihm](https://en.wikipedia.org/wiki/RSA_(cryptosystem))
* [TLS handshake](https://tools.ietf.org/html/rfc5246#section-7) (complicated function)
* [Basic TLS recieve function](https://tls.mbed.org/api/)
* [Basic TLS send function](https://tls.mbed.org/api/)
* Combine together existing AES and SHA modules with my code into application, which succesfully connects to server
* Patched [TLSEcho server for DebianOS](https://2ton.com.au/HeavyThing/#tlsechoserver) to print all debug information
* [Demo](http://recordit.co/Zxyxz2hlYl)

### What's left to do

* TEST!!! Main part was not enough tested
* TLS handshake. Make convinient function
* It is not real library now. I need to make real library :)

### Known Issues

* Encrypt premaster key can be incorrect
* Didn't test on chain of certificates

### Plans for the future

* Optimize some parts of code
* Add more cipher suits
* Write wiki page about library
* Add [extenstions](https://tools.ietf.org/html/rfc6066)
* Maintain library (TLS 1.3 is coming:))


### Demo
![](http://g.recordit.co/Zxyxz2hlYl.gif)