# Secure-Group-Chat
Secure Group Chat application using java remote method invokation.

## Project description
Each client is considered a server which apply Peer to Peer communication without the need to implement a server to handle the communications between all the clients. Each client send their certficates to the newly joined clients to the chat group and aggree to create a shared session key only between them. Using the newly created session key, all the communication between all the clintes should be encrypted.

## Project Goals
1. Sender and receiver should have self signed **certificate** then exchange the certificates (using RSA or ECC) in order to verify their identities.

2. It is required to have (diffie Hellman) agreement to get shared secret session key between the entities after verifying their identities.

3. Use the acquired session keys to create a cipher eg; DES, AES, etc..

4. Encrypt/Decrypt the messages using the created cipher.

## Goals achieved
1. Goal was achived using created **CertificateGenerator** object.
  * ECC keys were created using bouncy castle security library.
  
2. Goal was achived using the created **DHKeyGenerator** object.

3. & 4. Goals were achived using the created **EncryptDecrypt** object.
 
