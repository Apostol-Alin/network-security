# Answers lab 1

Exerices:
1. Basic concepts
    1. It is issued by `Let's Encrypt`.
    2. From 25 Feb 2026 to 26 May 2026.
    3. 2048 bits.
    4. The value is 010001 for both the certificate and for the certificate of the issuer. I notice that they are both the same. It doesn't impact security.
2. ...
3. ...
    1. `openssl genrsa -out private.key` 
    2. `openssl req -new -x509 -days 120 -key ./private.key -out ca.crt`
    3. I have read.
    4. `openssl genrsa -out sub.key 2048`
    5. `openssl req -new -key ./sub.key -out sub.csr`
    6. `openssl x509 -req -days 60 -in sub.csr -CA ./ca.crt -CAkey ./private.key -set_serial 02 -out sub.crt`
    7. `openssl x509 -text -noout -in sub.crt`
    8. `openssl pkcs12 -export -out sub.p12 -inkey sub.key -in sub.crt -chain -CAfile ca.crt`
    9. `openssl pkcs12 -info -in sub.p12`
4. ...
    1. Quantum threat means that, in the future, quantum computers could break RSA/ECC (algorithms used for SSL/TLS) exponentially faster than a normal computer. If that happens, attackers could forge certificate signatures, they could decrypt communication easily etc.
    2. To reduce risk and to make a better adoption process to post-quantum digital certificates, we should migrate to post-quantum algorithms and use a hybrid approach when it comes to creating certificates (basically a certificate holds two public keys and two signatures - classical and PQC).
    3. A lot of current companies rely on legacy software and updating that software to a whole new cryptographic standard could be quite cumbersome. Also, many companies rely on tools that automatically sign certificates so a company would have to wait for a version of that tool that supports post-quantum digital certificates.