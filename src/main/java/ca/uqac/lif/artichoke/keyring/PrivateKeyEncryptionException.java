package ca.uqac.lif.artichoke.keyring;

public class PrivateKeyEncryptionException extends Exception {

    public static final String DEFAULT_MSG = "An error occured during AES private key encryption";

    public PrivateKeyEncryptionException() {
        super(DEFAULT_MSG);
    }

}
