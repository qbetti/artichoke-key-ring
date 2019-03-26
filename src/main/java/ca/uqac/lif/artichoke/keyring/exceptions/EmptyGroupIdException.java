package ca.uqac.lif.artichoke.keyring.exceptions;

public class EmptyGroupIdException extends GroupIdException {

    private static final String DEFAULT_MSG = "Specified group ID is empty.";

    public EmptyGroupIdException() {
        super(DEFAULT_MSG);
    }
}
