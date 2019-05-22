package securechat;

import java.io.IOException;
import java.rmi.NotBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Timer;
import java.util.TimerTask;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    public static void main(String[] args) throws GeneralSecurityException, NoSuchAlgorithmException, IOException {
        //int pId = Integer.parseInt(args[0]);
        int pId = 2; // 0 -> process 1, 1 -> process 2 ,etc....
        try {
            System.out.println("Process: " + NodeI.services[pId]);
            Node obj = new Node(pId);
            initServer(obj);
            initClient(obj, pId);
        }
        catch (RemoteException e) {
            System.out.println(e.getMessage());
        }
        catch (NotBoundException e) {
            System.out.println(e.getMessage());
        }

    }

    public static void initServer(Node obj) throws RemoteException {
        Registry reg = LocateRegistry.createRegistry(obj.myPort);
        reg.rebind(obj.myService, obj);
    }

    private static void initClient(Node obj, int pId) throws RemoteException, NotBoundException {

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm");

        Timer timer = new Timer();
        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                try {
                    String recvMsg = obj.fetchNewMessages();
                    if (recvMsg.length() > 0) {
                        LocalDateTime now = LocalDateTime.now();
                        System.out.println(recvMsg + " " + dtf.format(now));
                    }
                }
                catch (RemoteException ex) {
                    Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
                }

            }
        }, 0, 100);

        while (true) {
            String msg = obj.scan.nextLine();
            //Get message from client console
            //Initialize message ID
            String mId = UUID.randomUUID().toString();
            String sender = obj.myService;

            //Create a message object to be sent (time-stamped with lClock value)
            Messages message = new Messages(mId, pId, sender, msg);

            obj.multicastMessages(message);

        }
    }
}
