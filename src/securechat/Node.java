package securechat;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.UnicastRemoteObject;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.PriorityQueue;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SealedObject;

public class Node extends UnicastRemoteObject implements NodeI {

    private static final long serialVersionUID = 1L;

    private final static int n = ipAddr.length;

    public int myPort;
    public String myIp, myService;
    public PriorityQueue<Messages> messageQueue;
    public Scanner scan;

    private boolean[] firstTimeCommunicating;
    private int serviceID;
    private PublicKey myKU, reciverKU;
    private PrivateKey myKR;
    private byte[] myByteKU, myByteKR, reciverByteKU;
    private byte[][] sharedSecretKey;
    private X509Certificate myCert, reciverCert;
    private EncryptDecrypt encryptDecrypt;
    private DHKeyGenerator diffieHellman;
    private String mAlgorithm = "ECC";

    protected Node(int idx) throws RemoteException, NoSuchAlgorithmException,
            GeneralSecurityException, IOException {
        serviceID = idx;
        myIp = ipAddr[idx];
        myPort = ports[idx];
        myService = services[idx];
        messageQueue = new PriorityQueue<Messages>();
        scan = new Scanner(System.in);
        CertificateGenerator keypairAndCertGen = new CertificateGenerator(mAlgorithm);
        myKU = keypairAndCertGen.getPublicKey();
        myKR = keypairAndCertGen.getPrivate();
        myByteKU = keypairAndCertGen.getPublicKeyBytes();
        myByteKR = keypairAndCertGen.getPrivateKeyBytes();
        myCert = keypairAndCertGen.generateCertificate("CN=" + myService + ", L=LONDON, C=GB", 1);
        encryptDecrypt = new EncryptDecrypt();
        firstTimeCommunicating = new boolean[n];
        for (int i = 0; i < n; i++) {
            firstTimeCommunicating[i] = true;
        }
        firstTimeCommunicating[idx] = false;
        sharedSecretKey = new byte[n][];
    }

    public void multicastMessages(Messages message) {
        for (int i = 0; i < n; i++) {
            try {
                if (!message.sender.equalsIgnoreCase(services[i])) {
                    if (firstTimeCommunicating[i]) {
                        firstTimeCommunicating[i] = false;
                        Registry reg = LocateRegistry.getRegistry(ports[i]);
                        NodeI e = (NodeI) reg.lookup(services[i]);
                        System.out.println("Sending my Certificate to " + NodeI.services[i]);
                        e.handCertificateToSide2(myCert, serviceID);
                        SealedObject sealdObject = encryptDecrypt.encryptAES(sharedSecretKey[i], message);
                        e.performMessages(sealdObject, serviceID);
                    }
                    else {
                        SealedObject sealdObject = encryptDecrypt.encryptAES(sharedSecretKey[i], message);
                        Registry reg = LocateRegistry.getRegistry(ports[i]);
                        NodeI e = (NodeI) reg.lookup(services[i]);
                        e.performMessages(sealdObject, serviceID);
                    }
                }
            }
            catch (Exception ex) {
                //Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                System.out.println("Reciver " + services[i] + " is down");
            }
        }
        //displayMessagess();
    }

    @Override
    public void performMessages(SealedObject message, int senderID) throws RemoteException, NotBoundException {
        try {
            firstTimeCommunicating[senderID] = false;
            System.out.println("Message recived...");
            System.out.println("Message will be decrypted using Diffie-Hellman...");
            Object decrypted = encryptDecrypt.decrypt(sharedSecretKey[senderID], message);
            messageQueue.add((Messages) decrypted);

        }
        catch (Exception ex) {
            Logger.getLogger(Node.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /*
    @fetchNewMessages return messages for others nodes, 
    and if node == itself, it will return blank
     */
    public String fetchNewMessages() throws RemoteException {
        if (messageQueue.size() > 0) {

            Messages t = messageQueue.poll();

            if (!t.sender.equalsIgnoreCase(myService)) {
                return "\t\t\t\t\t" + t;
            }
            else {
                return "";
            }
        }
        return "";
    }

    @Override
    public void handCertificateToSide1(X509Certificate senderCert, int senderID) {
        System.out.println("Recived " + NodeI.services[senderID] + " Certificate!\n\n\n\n");
        System.out.println(senderCert.toString());

        this.reciverCert = senderCert;
        reciverKU = reciverCert.getPublicKey();
        reciverByteKU = reciverKU.getEncoded();

        System.out.println("Verfying Certificate signature");
        try {
            reciverCert.verify(reciverKU);
        }
        catch (CertificateException | NoSuchAlgorithmException
                | InvalidKeyException | NoSuchProviderException
                | SignatureException ex) {
            System.out.println("Signature DOES NOT MATCH..ABORT "
                    + "COMMUNCATION CHANNEL");
            while (true) {
                System.out.println(".");
            }
        }
        System.out.println("Signature matched !");

        System.out.println("\nDiffie-Hellman time!");

    }

    @Override
    public void handCertificateToSide2(X509Certificate senderCert, int senderID) {
        try {
            System.out.println("\n\nRecived " + NodeI.services[senderID] + " Certificate!\n\n\n\n");
            System.out.println(senderCert.toString());
            Registry reg = LocateRegistry.getRegistry(ports[senderID]);
            NodeI e = (NodeI) reg.lookup(services[senderID]);
            System.out.println("Sending my Certificate to " + NodeI.services[senderID]);
            e.handCertificateToSide1(myCert, serviceID);

            this.reciverCert = senderCert;
            reciverKU = reciverCert.getPublicKey();
            reciverByteKU = reciverKU.getEncoded();

            System.out.println("Verfying Certificate signature");
            try {
                reciverCert.verify(reciverKU);
            }
            catch (CertificateException | NoSuchAlgorithmException
                    | InvalidKeyException | NoSuchProviderException
                    | SignatureException ex) {
                System.out.println("Signature DOES NOT MATCH..ABORT "
                        + "COMMUNCATION CHANNEL");
                while (true) {
                    System.out.println(".");
                }
            }
            System.out.println("Signature matched !");

            System.out.println("\nDiffie-Hellman time!\n");
            System.out.println("Switching to session keys instead of RSA");
            try {
                diffieHellman = new DHKeyGenerator();
                e.handDiffieHellmanKUTo1(diffieHellman.getPublicKeyBytes(), serviceID);
            }
            catch (NoSuchAlgorithmException | InvalidKeyException ex) {
                Logger.getLogger(Node.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        catch (RemoteException | NotBoundException ex) {
            Logger.getLogger(Node.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Override
    public void handDiffieHellmanKUTo1(byte[] senderDHKU, int senderID) {
        try {
            diffieHellman = new DHKeyGenerator(senderDHKU);
            sharedSecretKey[senderID] = diffieHellman.getSharedSecret();
            Registry reg = LocateRegistry.getRegistry(ports[senderID]);
            NodeI e = (NodeI) reg.lookup(services[senderID]);
            e.handDiffieHellmanKUTo2(diffieHellman.getPublicKeyBytes(), serviceID);
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException
                | InvalidAlgorithmParameterException
                | InvalidKeyException | RemoteException | NotBoundException ex) {
            Logger.getLogger(Node.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    @Override
    public void handDiffieHellmanKUTo2(byte[] senderDHKU, int senderID) {
        try {
            diffieHellman.setupAgreement(senderDHKU);
            sharedSecretKey[senderID] = diffieHellman.getSharedSecret();
        }
        catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException ex) {
            Logger.getLogger(Node.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

}
