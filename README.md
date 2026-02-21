# Simple Server/Client Post Quantum Hybrid Key Exchange program

## Table of Contents

Here's how I've organized my README:
- [Project Overview](#project-overview)
- [How to Install](#requirements)
- [Usage Examples](#how-to-use)
- [How to Contribute](#contributing)


## Project Overview

I created this project to learn how to use OpenSSL C API and how Key Exchange Mechanisms works, and how to make it hybrid. 

### Key Focus Areas
- Primary goal I achieved: Learn how OpenSSL works and how to generate post quantum and classic cryptographic artifacts.
- Unique value I provide: mlkem_utils.h/c makes life easier when developing OpenSSL apps.

### Possible future work ideas
- Split the socket and cryptographic functions into different headers
- Add command line arguments for specifying the IP of the server, or the port used, for example.
- Add waiting into the client in case the server is not up.
- Add unit testing and test cases.

All help or new ideas are welcome! :)

## Requirements
To build this project, you will need the following packages:
- GCC compiler
- OpenSSL >= 3.5.x. This version includes the Post Quantum Cryptographic support, needed to generate the ML-KEM key pair.
- Make
- 
## Installation
First, clone the repository into your machine.
```bash
https://github.com/imorlxs/hybrid-pqc-openssl.git
```

To compile it, simple execute
```bash
make
```
It will generate two binaries, `server_app` and `client_app`.

## How to use
Open two terminal and execute both programs. You **MUST** execute the server first, or the client will not open.

Server output example:
```
Waiting connections in port 9001...
Client connected.
Public keys sent.

--- Shared Secrets (Server) ---
X25519 (32 bytes): 14DA62A8A5FD61C90888B30056EBA59F3FE37EA86B8A15005ED93618CBFF9329
ML-KEM-768 (32 bytes): 4B6A6BD56803DDD229FBE38ACCA8A52CAA182C4BCA520D1D497E9E819D5E8C2E
Final AES key (32 bytes): F777CCAF1685749C8E6A52F2B2495D4FAAA593E61F9804597A657C12C3C908A3
Decrypted message: Hello world!
```

Client output example:
```
Connected to the server.

--- Shared Secrets (Client) ---
X25519 (32 bytes): 14DA62A8A5FD61C90888B30056EBA59F3FE37EA86B8A15005ED93618CBFF9329
ML-KEM-768 (32 bytes): 4B6A6BD56803DDD229FBE38ACCA8A52CAA182C4BCA520D1D497E9E819D5E8C2E

Cypher texts sent to the server .
Final AES key (32 bytes): F777CCAF1685749C8E6A52F2B2495D4FAAA593E61F9804597A657C12C3C908A3
Encrypted message sent.
```
## Contributing

I welcome contributions! Here's how you can help improve my project:

1. Fork my repository
2. Create your feature branch `git checkout -b feature/your-idea`
3. Commit your changes `git commit -m 'Add your feature'`
4. Push to branch `git push origin feature/your-idea`
5. Open a pull request

I review all PRs and appreciate your help!
