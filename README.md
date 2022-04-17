# HTTPS Web Server
This is a web server. The code is C++17. The implementations for HTTP/1.1 and TLS/1.2 are my own.
Connection handling is non-blocking, multiplexing, and concurrent.
I am running this on my Raspberry Pi at freddiewoodruff.co.uk.
I am using my own elliptic curve implementations for key-exchange and signatures.

Out on the web there seem to be bots probing every attack surface within the HTTP and TLS layers.
This has thrown up many curiosities and helped me harden the server.
