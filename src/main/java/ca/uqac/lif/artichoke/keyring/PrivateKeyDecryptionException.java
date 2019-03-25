package ca.uqac.lif.artichoke.keyring;

public class PrivateKeyDecryptionException extends Exception {

    public static final String DEFAULT_MSG = "An error occured during AES private key decryption";

    public PrivateKeyDecryptionException() {
        super(DEFAULT_MSG);
    }
}
