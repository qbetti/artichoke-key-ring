package ca.uqac.lif.artichoke.keyring;

public class GroupIdAlreadyExistsException extends Exception {

    private static final String MSG_TO_FORMAT = "Group with id '%s' already exists in keyring file '%s' and cannot be overridden.";
    private static final String DEFAULT_MSG = "Group with id '%s' already exists in specified keyring file and cannot be overridden.";


    public GroupIdAlreadyExistsException(String groupId) {
        super(String.format(DEFAULT_MSG, groupId));
    }

    public GroupIdAlreadyExistsException(String groupId, String keyRingFilePath) {
        super(String.format(MSG_TO_FORMAT, groupId, keyRingFilePath));
    }

}
