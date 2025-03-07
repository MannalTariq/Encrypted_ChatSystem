# Encrypted_ChatSystem
AES128-and-SHA256 encrypted chatting between server and client

# Secure Chat System with Registration, Login, and Encrypted Communication
**Overview**
This project implements a secure chat system where users can register, log in, and communicate with each other securely. The system uses cryptographic techniques such as password hashing and encryption to ensure the confidentiality and integrity of user credentials and messages. **The chat system follows a client-server model and utilizes Diffie-Hellman key exchange, AES-128 encryption, and SHA-256 hashing with salt for secure communication and credential management.**

**Features**
1. User Registration: Allows users to register with a unique username, email, and password. User credentials are encrypted before being sent and securely stored in a file.
2. User Authentication: Uses **SHA-256 hashing with salt** to securely store and verify passwords. Users must log in with valid credentials before accessing the chat system.
3. Encrypted Communication: After a successful login, the client and server exchange messages using **AES-128 encryption**, ensuring confidentiality.
4. **Diffie-Hellman Key Exchange**: Ensures secure key exchange between client and server for message encryption.
Credential Storage: User credentials (username, email, **hashed password with salt**) are stored securely.
