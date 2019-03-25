package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.Security;
import java.util.Scanner;

public class CmdApp {

    private final static CommandLineParser CMD_PARSER = new DefaultParser();
    private final static String DEFAULT_FILE_PATH = "./keyring.json";


    private Options options;
    private CommandLine cmd;

    private Option optGenerateNewKeyRing;
    private Option optKeyRingFilePath;
    private Option optAddGroup;
    private Option optRetrieveGroup;
    private Option optStayUnlocked;
    private Option optGroupId;
    private Option optGroupKey;
    private Option optHelp;

    private String keyringFilePath;


    public CmdApp() {
        buildOptions();
    }


    private void buildOptions() {
        optGenerateNewKeyRing = Option.builder("new")
                .longOpt("generate-new")
                .hasArg(false)
                .desc("Generates a new keyring JSON file")
                .build();

        optKeyRingFilePath = Option.builder("f")
                .longOpt("file")
                .hasArg()
                .desc("Specifies the name of the key-ring JSON file to use/create")
                .build();

        optAddGroup = Option.builder("a")
                .longOpt("add")
                .hasArg(false)
                .desc("Add a new group id and its secret key to the key-ring")
                .build();

        optRetrieveGroup = Option.builder("r")
                .longOpt("retrieve")
                .hasArg(false)
                .desc("Retrieve the secret key of a group with its given group id")
                .build();

        optStayUnlocked = Option.builder("u")
                .longOpt("unlock")
                .hasArg(false)
                .desc("True if the key-ring should stay unlocked for the following actions. " +
                        "False by default, will ask the passphrase for each action")
                .build();

        optGroupId = Option.builder("gid")
                .longOpt("group-id")
                .hasArg(true)
                .desc("Specifies the id of the group to be added/retrieved")
                .build();

        optGroupKey = Option.builder("gk")
                .longOpt("group-key")
                .hasArg()
                .desc("Specifies the secret key in HEXADECIMAL of the group to be added")
                .build();

        optHelp = Option.builder("h")
                .longOpt("help")
                .hasArg(false)
                .desc("Print this message")
                .build();

        options = new Options();
        options.addOption(optGenerateNewKeyRing)
                .addOption(optKeyRingFilePath)
                .addOption(optAddGroup)
                .addOption(optRetrieveGroup)
                .addOption(optStayUnlocked)
                .addOption(optGroupId)
                .addOption(optGroupKey)
                .addOption(optHelp)
                .addOption(optHelp);
    }


    private void run(String[] args) throws ParseException {
        try {
            cmd = CMD_PARSER.parse(options, args);

            if(cmd.hasOption(optHelp.getOpt())) {
                printHelp();
                return;
            }

            if(cmd.hasOption(optKeyRingFilePath.getOpt())) {
                keyringFilePath = cmd.getOptionValue(optKeyRingFilePath.getOpt());

            } else {
                keyringFilePath = DEFAULT_FILE_PATH;
            }

            if(cmd.hasOption(optGenerateNewKeyRing.getOpt())) {
                generateNewKeyRingFile();
            } else {
                String passphrase = askPassphrase();
                String groupId = cmd.getOptionValue(optGroupId.getOpt());


                    if (cmd.hasOption(optAddGroup.getOpt())) {
                        addGroup(passphrase, groupId);

                    } else if (cmd.hasOption(optRetrieveGroup.getOpt())) {
                        retrieveGroup(passphrase, groupId);

                    } else {

                    }

            }
        } catch (IOException e) {
            System.out.println("Could not create/write or open/read'" + keyringFilePath + "' file.\nCheck path and/or permissions.");
            System.exit(-1);
        } catch (EmptyGroupIdException | NonExistingGroupIdException | BadPassphraseException | GroupIdAlreadyExistsException | PrivateKeyDecryptionException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }

    private void printHelp() {
        HelpFormatter formatter = new HelpFormatter();
        formatter.printHelp("java -jar key-ring.jar", options);
    }


    private boolean generateNewKeyRingFile()
            throws IOException {

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


    private boolean addGroup(String passphrase, String groupId)
            throws IOException, PrivateKeyDecryptionException, GroupIdAlreadyExistsException, EmptyGroupIdException, BadPassphraseException {

        KeyRing keyRing = KeyRing.loadFromFile(new File(keyringFilePath), passphrase);

        byte[] groupKey;
        if (cmd.hasOption(optGroupKey.getOpt())) {
            groupKey = HexString.decode(cmd.getOptionValue(optGroupKey.getOpt()));
        } else {
            groupKey = AESEncryption.generateNewKey().getEncoded();
        }

        keyRing.addGroup(groupId, groupKey);
        keyRing.saveToFile(new File(keyringFilePath));
        System.out.println(HexString.encode(groupKey));

        return true;
    }


    private boolean retrieveGroup(String passphrase, String groupId)
            throws IOException, PrivateKeyDecryptionException, NonExistingGroupIdException, BadPassphraseException {

        KeyRing keyRing = KeyRing.loadFromFile(new File(keyringFilePath), passphrase);
        byte[] key = keyRing.retrieveGroupKey(groupId);
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
        String passphrase = getInputLine("Choose a passphrase (!! DO NOT FORGET IT, IT CANNOT BE RECOVERED !!): ");
        String verification = getInputLine("Confirm your passphrase: ");

        if (passphrase.isEmpty()) {
            System.out.println("You cannot choose an empty passphrase.");
            return null;
        }

        if(!passphrase.equals(verification)) {
            System.out.println("Passphrase and verification do not match.");
            return null;
        }
        return passphrase;
    }


    private String getInputLine(String msg) {
        Console console = System.console();
        if(console == null) {
            System.out.println(msg);
            Scanner scanner = new Scanner(System.in);
            return scanner.nextLine();
        } else {
            return new String(console.readPassword(msg));
        }
    }


    private String askPassphrase() {
        return getInputLine("Passphrase: ");
    }


    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        CmdApp app = new CmdApp();
        try {
            app.run(args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }
}
