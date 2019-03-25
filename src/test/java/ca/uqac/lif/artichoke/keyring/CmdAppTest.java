package ca.uqac.lif.artichoke.keyring;

import ca.uqac.lif.artichoke.keyring.crypto.AESEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.ECEncryption;
import ca.uqac.lif.artichoke.keyring.crypto.SCrypt;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class CmdAppTest {

    @Test
    public void testPrintHelp() {
        CmdApp.main(new String[]{"--help"});
    }

    @Test
    public void testGenerateNew() {
        CmdApp.main(new String[]{"--generate-new"});
    }

}