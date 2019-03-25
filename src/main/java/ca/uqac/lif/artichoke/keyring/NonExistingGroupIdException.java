package ca.uqac.lif.artichoke.keyring;

public class NonExistingGroupIdException extends Exception {

    private static final String DEFAULT_MSG = "Group with id '%s' does not exist in specified keyring file.";


    public NonExistingGroupIdException(String groupId) {
        super(String.format(DEFAULT_MSG, groupId));
    }

}
