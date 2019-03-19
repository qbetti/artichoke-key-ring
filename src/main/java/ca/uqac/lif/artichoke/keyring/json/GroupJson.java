package ca.uqac.lif.artichoke.keyring.json;

public class GroupJson {

    private String id;
    private PrivateKeyJson secretKey;

    public GroupJson() {
        secretKey = new PrivateKeyJson();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public PrivateKeyJson getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(PrivateKeyJson secretKey) {
        this.secretKey = secretKey;
    }
}
