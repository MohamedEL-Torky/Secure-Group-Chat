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
 
## How to run:
1. Import the project to netbeans/Eclipse whatever IDE you're using

2. Add bouncy castle library you will find it under /dist/lib/bcprov-jdk15on-161.jar

3. In Main.java line **22** change it to 0 then run the main java file, then change it to 1 and run it again. Keep doing this step till you reach the last number in java interface NodeI.java variable **numberOFNodes** -1

### Note:
You can change the **numberOFNodes** in the interface and add more clients to be instantiated for example:

---
If you want to add one more client to be total of 4 clients, You will have to edit the interface class NodeI.java only.

#### Go to NodeI.java edit the following:
* **numberOFNodes** -> 4
* **ipAddr** -> {"127.0.0.1", "127.0.0.1", "127.0.0.1", "127.0.0.1"};
* **services** -> {"Alice", "Bob", "Larry", "Carol"};
* **ports** -> {2000, 3000, 4000, 5000};

Note that, when you run the java file for that specific client for example Alice which run on localhost:2000 you might get registery exception because there is another service on your pc use the same port **2000**. So all what you have to do is to change 2000 to any port number in the NodeI.java
