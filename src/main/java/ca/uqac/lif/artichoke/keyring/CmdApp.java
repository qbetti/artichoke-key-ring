package ca.uqac.lif.artichoke.keyring;

import org.apache.commons.cli.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.security.Security;

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
    private Option optGroupdId;
    private Option optGroupKey;
    private Option optHelp;

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

        optGroupdId = Option.builder("gid")
                .longOpt("group-id")
                .hasArg()
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
                .addOption(optGroupdId)
                .addOption(optGroupKey)
                .addOption(optHelp)
                .addOption(optHelp);
    }

    private void run(String[] args) throws ParseException {
        cmd = CMD_PARSER.parse(options, args);

        if(cmd.hasOption(optHelp.getOpt())) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("java -jar key-ring.jar", options);
            return;
        }

        if(cmd.hasOption(optGenerateNewKeyRing.getOpt())) {
            generateNewKeyRingFile();
        }
    }

    private boolean generateNewKeyRingFile() {
        String filePath;
        if(cmd.hasOption(optKeyRingFilePath.getOpt()))
            filePath = cmd.getOptionValue(optKeyRingFilePath.getOpt());
        else
            filePath = DEFAULT_FILE_PATH;

        File keyRingFile = new File(filePath);
        try {
            if(keyRingFile.createNewFile()) {
                String passphrase = null;
                while(passphrase == null) {
                    passphrase = askNewPassphrase();
                }

                KeyRing keyRing = KeyRing.generateNew(passphrase, false);
                keyRing.saveToFile(keyRingFile);
                return true;

            } else {
                System.out.println("File '"+ filePath + "' already exists.");
                return false;
            }
        } catch (IOException e) {
            System.out.println("Could not create/write file '"+ filePath + "', check path or permissions");
            return false;
        }
    }

    private String askNewPassphrase() {
        Console console = System.console();
        String passphrase = new String(console.readPassword("Choose a passphrase (IT CANNOT BE RECOVERED): "));
        String verification = new String(console.readPassword("Confirm your passphrase: "));

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

    private String askPassphrase() {
        Console console = System.console();
        return new String(console.readPassword("Passphrase: "));
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        CmdApp app = new CmdApp();
        try {
            app.run(args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
        }
    }


}
