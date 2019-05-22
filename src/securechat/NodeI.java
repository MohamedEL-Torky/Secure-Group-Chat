package securechat;

import java.rmi.NotBoundException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.security.cert.X509Certificate;
import javax.crypto.SealedObject;

public interface NodeI extends Remote {

    int numberOFNodes = 4;
    String[] ipAddr = {"127.0.0.1", "127.0.0.1", "127.0.0.1"};
    String[] services = {"Alice", "Bob", "Larry"};
    Integer[] ports = {2000, 3000, 4000};

    void performMessages(SealedObject message, int senderID) throws RemoteException, NotBoundException;

    void handCertificateToSide1(X509Certificate reciverCert, int serviceID) throws RemoteException, NotBoundException;

    void handCertificateToSide2(X509Certificate senderCert, int serviceID) throws RemoteException, NotBoundException;

    void handDiffieHellmanKUTo1(byte[] senderDHKU, int serviceID) throws RemoteException, NotBoundException;

    void handDiffieHellmanKUTo2(byte[] senderDHKU, int serviceID) throws RemoteException, NotBoundException;
}
