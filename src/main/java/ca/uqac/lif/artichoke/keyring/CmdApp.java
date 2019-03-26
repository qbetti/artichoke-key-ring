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


    public CmdApp(String[] args) throws ParseException {
        buildOptions();
        parse(args);
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

    public void initApp(App app) {
        app.setOptions(options);

        app.setPrintHelpMode(cmd.hasOption(optHelp.getOpt()));
        app.setGenerateNewKeyRingMode(cmd.hasOption(optGenerateNewKeyRing.getOpt()));
        app.setAddGroupMode(cmd.hasOption(optAddGroup.getOpt()));
        app.setRetrieveGroupMode(cmd.hasOption(optRetrieveGroup.getOpt()));
        app.setStayUnlocked(cmd.hasOption(optStayUnlocked.getOpt()));

        app.setKeyringFilePath(cmd.getOptionValue(optKeyRingFilePath.getOpt()));
        app.setGroupId(cmd.getOptionValue(optGroupId.getOpt()));
        app.setHexGroupKey(cmd.getOptionValue(optGroupKey.getOpt()));
    }

    private void parse(String[] args) throws ParseException {
        cmd = CMD_PARSER.parse(options, args);
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            CmdApp cmdApp = new CmdApp(args);
            App app = new App();
            cmdApp.initApp(app);
            app.run();
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            System.exit(-1);
        }
    }
}
