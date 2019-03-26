package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import ca.uqac.lif.artichoke.keyring.exceptions.BadPassphraseException;
import ca.uqac.lif.artichoke.keyring.exceptions.GroupIdException;
import ca.uqac.lif.artichoke.keyring.exceptions.PrivateKeyDecryptionException;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class App {

    private final static String DEFAULT_FILE_PATH = "./keyring.json";

    private Options options;

    private boolean printHelpMode;
    private boolean generateNewKeyRingMode;
    private boolean addGroupMode;
    private boolean retrieveGroupMode;
    private boolean stayUnlocked;

    private String keyringFilePath;
    private String groupId;
    private String hexGroupKey;


    public App() {
    }

    public void run() {
        if(printHelpMode) {
            printHelp();
            System.exit(0);
        }

        if(!generateNewKeyRingMode && !addGroupMode && !retrieveGroupMode) {
            System.out.println("Please specify an action to perform.");
            printHelp();
            System.exit(-1);
        }
        else if(!(generateNewKeyRingMode ^ addGroupMode ^ retrieveGroupMode)) {
            System.out.println("Generating a new file, adding or retrieving a group key cannot be done at the same time.");
            printHelp();
            System.exit(-1);
        }

        try {
            if (generateNewKeyRingMode) {
                generateNewKeyRingFile();
            }
            else {
                File keyringFile = new File(keyringFilePath);
                KeyRing keyRing = KeyRing.loadFromFile(keyringFile);

                String passphrase = askPassphrase();
                if (!keyRing.verifyPassphrase(passphrase)) {
                    throw new BadPassphraseException();
                }

                if (addGroupMode) {
                    addGroup(keyRing, passphrase);
                    keyRing.saveToFile(keyringFile);
                }
                else if (retrieveGroupMode) {
                    retrieveGroup(keyRing, passphrase);
                }
            }
        }
        catch (IOException e) {
            System.out.println("Error: " + e.getMessage());
            System.exit(-1);
        }
        catch (GroupIdException | BadPassphraseException | PrivateKeyDecryptionException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }


    private boolean generateNewKeyRingFile() throws IOException {
        File keyRingFile = new File(keyringFilePath);
        keyRingFile.createNewFile();

        String passphrase = null;
        while(passphrase == null) {
            passphrase = askNewPassphrase();
        }

        KeyRing keyRing = KeyRing.generateNew(passphrase, false);
        keyRing.saveToFile(keyRingFile);
        return true;
    }


    private boolean addGroup(KeyRing keyRing, String passphrase) throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {
        byte[] groupKey;
        if (hexGroupKey != null && !hexGroupKey.isEmpty()) {
            groupKey = HexString.decode(hexGroupKey);
        }
        else {
            groupKey = AESEncryption.generateNewKey().getEncoded();
        }

        keyRing.addGroup(passphrase, groupId, groupKey);
        return true;
    }


    private boolean retrieveGroup(KeyRing keyRing, String passphrase) throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {
        byte[] key = keyRing.retrieveGroupKey(passphrase, groupId);
        if(key == null) {
            System.out.println("Could not get secret key for '" + groupId + "' group.");
            System.exit(-1);
        }
        else {
            System.out.println("Secret key ('" + groupId + "'): " + HexString.encode(key));
        }
        return true;
    }


    private String askNewPassphrase() {
        String passphrase = getPassword("Choose a passphrase (!! DO NOT FORGET IT, IT CANNOT BE RECOVERED !!): ");
        String verification = getPassword("Confirm your passphrase: ");

        if (passphrase.trim().isEmpty()) {
            System.out.println("You cannot choose an empty passphrase.");
            return null;
        }

        if(!passphrase.equals(verification)) {
            System.out.println("Passphrase and verification do not match.");
            return null;
        }
        return passphrase;
    }


    private String askPassphrase() {
        return getPassword("Passphrase: ");
    }


    private String getPassword(String msg) {
        Console console = System.console();
        if(console == null) {
            System.out.println(msg);
            Scanner scanner = new Scanner(System.in);
            return scanner.nextLine();
        } else {
            return new String(console.readPassword(msg));
        }
    }


    private void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar key-ring.jar", options);
    }


    public void setOptions(Options options) {
        this.options = options;
    }

    public void setPrintHelpMode(boolean printHelpMode) {
        this.printHelpMode = printHelpMode;
    }

    public void setGenerateNewKeyRingMode(boolean generateNewKeyRingMode) {
        this.generateNewKeyRingMode = generateNewKeyRingMode;
    }

    public void setAddGroupMode(boolean addGroupMode) {
        this.addGroupMode = addGroupMode;
    }

    public void setRetrieveGroupMode(boolean retrieveGroupMode) {
        this.retrieveGroupMode = retrieveGroupMode;
    }

    public void setStayUnlocked(boolean stayUnlocked) {
        this.stayUnlocked = stayUnlocked;
    }

    public void setKeyringFilePath(String keyringFilePath) {
        if(keyringFilePath == null || keyringFilePath.trim().isEmpty())
            this.keyringFilePath = DEFAULT_FILE_PATH;
        else
            this.keyringFilePath = keyringFilePath;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId;
    }

    public void setHexGroupKey(String hexGroupKey) {
        if(hexGroupKey == null || hexGroupKey.trim().isEmpty())
            this.hexGroupKey = null;
        else {
            this.hexGroupKey = hexGroupKey.trim()
                    .replaceAll("\"", "")
                    .replaceAll("'", "")
                    .replaceAll("0x", "");
        }
    }
}
