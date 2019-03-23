package ca.uqac.lif.artichoke.keyring.json;

import java.util.ArrayList;
import java.util.List;

public class KeyRingJson {

    private String publicKey;
    private EncryptedField privateKey;
    private String salt;
    private List<GroupJson> groups;

    public KeyRingJson() {
        privateKey = new EncryptedField();
        groups = new ArrayList<>();
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public EncryptedField getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(EncryptedField privateKey) {
        this.privateKey = privateKey;
    }

    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public List<GroupJson> getGroups() {
        return groups;
    }
}
