package ca.uqac.lif.artichoke.keyring;

import org.bouncycastle.crypto.generators.SCrypt;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.util.logging.Logger;

public class EncryptionKeyFactory {

    private final static Logger logger = Logger.getLogger(EncryptionKeyFactory.class.getCanonicalName());

    private static final String CURVE_NAME = "secp256k1";
    private static final int DEFAULT_AES_KEY_SIZE = 256; // in bits
    private static final int DEFAULT_SCRYPT_SALT_SIZE = 32; // in bytes

    /**
     * Generates an elliptic curve key pair based on the "secp256k1" curve
     * @return the key pair
     */
    public static KeyPair generateECKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
            gen.initialize(new ECGenParameterSpec(CURVE_NAME));
            return gen.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            logger.severe(e.toString());
            System.exit(-1);
            return null;
        }
    }

    /**
     * Generates a 256-bit AES key
     * @return the AES key
     */
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES", "BC");
            gen.init(DEFAULT_AES_KEY_SIZE);
            return gen.generateKey();
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            logger.severe(e.toString());
            System.exit(-1);
            return null;
        }
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase and salt using the
     * Scrypt derivation function
     * @param passphrase the passphrase
     * @param salt the salt
     * @return
     */
    public static byte[] generateDerivedKey(byte[] passphrase, byte[] salt) {
        return SCrypt.generate(passphrase, salt, 262144, 8, 1, 32);
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase and salt using the
     * Scrypt derivation function
     * @param passphrase the passphrase
     * @param hexSalt the hexadecimal representation of the salt
     * @return
     */
    public static byte[] generateDerivedKey(String passphrase, String hexSalt) {
        return generateDerivedKey(passphrase.getBytes(), HexString.decode(hexSalt));
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase and a random 256-bit salt
     * using the Scrypt derivation function
     * @param passphrase the passphrase to derive the key from
     * @return the following array:
     *          <ul>
     *              <li>0 - {@code byte[]} the key derived from the passphrase</li>
     *              <li>1 - {@code byte[]} the salt used for the derivation</li>
     *          </ul>
     */
    public static byte[][] generateDerivedKey(String passphrase) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[DEFAULT_SCRYPT_SALT_SIZE];
        random.nextBytes(salt);

        return new byte[][]{
                generateDerivedKey(passphrase.getBytes(), salt),
                salt
        };
    }
}
