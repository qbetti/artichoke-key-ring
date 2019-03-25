package ca.uqac.lif.artichoke.keyring;

public class EmptyGroupIdException extends Exception {

    private static final String DEFAULT_MSG = "Specified group ID is empty.";

    public EmptyGroupIdException() {
        super(DEFAULT_MSG);
    }
}
