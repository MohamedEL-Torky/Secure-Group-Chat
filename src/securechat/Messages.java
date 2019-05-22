package securechat;

import java.io.Serializable;

public class Messages implements Serializable {

    private static final long serialVersionUID = 1L;

    String mId, sender, sentMsg;
    int pId;

    public Messages(String mId, int pId, String sender, String sentMsg) {
        this.mId = mId;
        this.pId = pId;
        this.sender = sender;
        this.sentMsg = sentMsg;
    }

    @Override
    public String toString() {
        return sender + ": " + sentMsg;
    }

}
