package ca.uqac.lif.artichoke.keyring.exceptions;

public class DuplicatedGroupIdException extends GroupIdException {

    private static final String MSG_TO_FORMAT = "KeyRingGroup with id '%s' already exists in keyring file '%s' and cannot be overridden.";
    private static final String DEFAULT_MSG = "KeyRingGroup with id '%s' already exists in specified keyring file and cannot be overridden.";


    public DuplicatedGroupIdException(String groupId) {
        super(String.format(DEFAULT_MSG, groupId));
    }

    public DuplicatedGroupIdException(String groupId, String keyRingFilePath) {
        super(String.format(MSG_TO_FORMAT, groupId, keyRingFilePath));
    }

}
