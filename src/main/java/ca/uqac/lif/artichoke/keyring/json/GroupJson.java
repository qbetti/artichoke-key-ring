package ca.uqac.lif.artichoke.keyring.json;

public class GroupJson {

    private String id;
    private EncryptedField secretKey;

    public GroupJson() {
        secretKey = new EncryptedField();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public EncryptedField getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(EncryptedField secretKey) {
        this.secretKey = secretKey;
    }
}
