package ca.uqac.lif.artichoke.keyring;

public class KeyRingGroup {

    private String id;
    private String hexEncryptedSecretKey;
    private String hexIvSecretKey;

    public KeyRingGroup(String id, String hexEncryptedSecretKey, String hexIvSecretKey) {
        this.id = id;
        this.hexEncryptedSecretKey = hexEncryptedSecretKey;
        this.hexIvSecretKey = hexIvSecretKey;
    }


    public String getId() {
        return id;
    }

    public String getHexEncryptedSecretKey() {
        return hexEncryptedSecretKey;
    }

    public String getHexIvSecretKey() {
        return hexIvSecretKey;
    }
}
