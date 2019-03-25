package ca.uqac.lif.artichoke.keyring;

public class BadPassphraseException extends Exception {

    private static final String MSG_TO_FORMAT = "Wrong passphrase for '%s' keyring file.";
    private static final String DEFAULT_MSG = "Wrong passphrase for specified keyring file.";

    public BadPassphraseException() {
        super(DEFAULT_MSG);
    }

    public BadPassphraseException(String keyRingFilePath) {
        super(String.format(MSG_TO_FORMAT, keyRingFilePath));
    }

}
