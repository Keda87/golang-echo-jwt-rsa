# golang-echo-jwt-rsa
POC using JWT authentication with RSA as the signing key.

### How to Generate Private & Public Key
```bash
$ ssh-keygen -t rsa -b 4096 -m PEM -f example.key                   # generate private key without password.
$ openssl rsa -in example.key -pubout -outform PEM -out example.pem # generate public key.
```
