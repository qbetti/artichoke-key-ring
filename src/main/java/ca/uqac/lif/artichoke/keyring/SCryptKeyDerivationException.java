package ca.uqac.lif.artichoke.keyring;

public class SCryptKeyDerivationException extends Exception {

    private static final String DEFAULT_MSG = "An error occurred during key derivation with the specified passphrase";

    public SCryptKeyDerivationException() {
        super(DEFAULT_MSG);
    }

}
