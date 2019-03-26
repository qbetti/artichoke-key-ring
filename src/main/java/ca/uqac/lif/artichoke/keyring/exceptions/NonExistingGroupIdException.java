package ca.uqac.lif.artichoke.keyring.exceptions;

public class NonExistingGroupIdException extends GroupIdException {

    private static final String DEFAULT_MSG = "KeyRingGroup with id '%s' does not exist in specified keyring file.";


    public NonExistingGroupIdException(String groupId) {
        super(String.format(DEFAULT_MSG, groupId));
    }

}
