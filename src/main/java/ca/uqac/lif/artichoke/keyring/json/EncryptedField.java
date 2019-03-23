package ca.uqac.lif.artichoke.keyring.json;

public class EncryptedField {

    private String cipher;
    private String iv;

    public String getCipher() {
        return cipher;
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }
}
