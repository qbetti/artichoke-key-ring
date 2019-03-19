package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * Provides a wrapper around elliptic curve signature generation/verification from BouncyCastle
 * and key pair generation.
 * The signing algorithm used is {@value #SIGNATURE_ALGO}, which is the ECDSA algorithm
 * with data hash function SHA1.
 * The curve used for key generation and signature is the {@value DEFAULT_CURVE_NAME} curve.
 */
public class ECEncryption {

    /**
     * Elliptic curve algorithm
     */
    public static final String EC = "EC";

    /**
     * Full algorithm for signing
     */
    private static final String SIGNATURE_ALGO = "SHA1withECDSA";

    /**
     * The curve used for key generation and signing
     */
    private static final String DEFAULT_CURVE_NAME = "secp256k1";

    /**
     * The size in bytes of the private key
     */
    public static final int PRIVATE_KEY_SIZE = 32; // in bytes

    /**
     * The private key
     */
    private ECPrivateKey privateKey;

    /**
     * The public key
     */
    private ECPublicKey publicKey;

    /**
     * Constructor by specifying the private and public keys
     * @param privateKey the private key (should be castable to {@link ECPrivateKey})
     * @param publicKey the public key (should be castable to {@link ECPublicKey})
     */
    public ECEncryption(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = (ECPrivateKey) privateKey;
        this.publicKey = (ECPublicKey) publicKey;
    }

    /**
     * Constructor by specifying the private and public keys
     * @param hexPrivateKey the hexadecimal-encoded private key (ONLY the value of the integer)
     * @param hexPublicKey the hexadecimal-encoded public key (ONLY the EC point coordinates)
     */
    public ECEncryption(String hexPrivateKey, String hexPublicKey) {
        this(decodePrivateKey(hexPrivateKey), decodePublicKey(hexPublicKey));
    }

    /**
     * Constructor by specifying the key pair
     * @param keyPair the key pair (should hold EC keys)
     */
    public ECEncryption(KeyPair keyPair) {
        this(keyPair.getPrivate(), keyPair.getPublic());
    }

    /**
     * Constructor generating a new EC key pair
     * for the {@value DEFAULT_CURVE_NAME} curve
     */
    public ECEncryption() {
        this(generateNewKeys());
    }

    /**
     * Generates a new EC key pair
     * for the {@value DEFAULT_CURVE_NAME} curve
     */
    public static KeyPair generateNewKeys() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(EC, "BC");
            gen.initialize(new ECGenParameterSpec(DEFAULT_CURVE_NAME));
            return gen.generateKeyPair();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    /**
     * Signs data using {@value SIGNATURE_ALGO}
     * @param data the data to use for signature
     * @return the signature, or null if something goes wrong
     */
    public ECSignature sign(byte[] data) {
        Signature ecdsa = null;
        try {
            ecdsa = Signature.getInstance(SIGNATURE_ALGO);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.initSign(this.privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return new ECSignature(ecdsa.sign());
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verifies a signature with the signed data
     * @param hexSignature the hexadecimal-encoded signature
     * @param data the expected signed data
     * @return true if the signature is correct, false otherwise
     */
    public boolean verifySignature(String hexSignature, byte[] data) {
        return verifySignature(new ECSignature(hexSignature), data);
    }


    /**
     * Verifies a signature with the signed data
     * @param signature the signature
     * @param data the expected signed data
     * @return true if the signature is correct, false otherwise
     */
    public boolean verifySignature(ECSignature signature, byte[] data) {
        return verifySignature(signature.getBytes(), data);
    }

    /**
     * Verifies a signature with the signed data
     * @param signature the signature
     * @param data the expected signed data
     * @return true if the signature is correct, false otherwise
     */
    public boolean verifySignature(byte[] signature, byte[] data) {
        Signature ecdsa = null;
        try {
            ecdsa = Signature.getInstance(SIGNATURE_ALGO);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.initVerify(this.publicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return ecdsa.verify(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Formats a private key so that it corresponds to a 32-byte long array
     * @param privateKey the private key to format
     * @return a 32-byte long array containing the key
     */
    private static byte[] formatPrivateKey(ECPrivateKey privateKey) {
        return formatPrivateKey(privateKey.getD().toByteArray());
    }

    /**
     * Formats a private key so that it corresponds to a 32-byte long array
     * @param privateKeyBytes the private key's integer bytes
     * @return a 32-byte long array containing the key
     */
    private static byte[] formatPrivateKey(byte[] privateKeyBytes) {
        if(PRIVATE_KEY_SIZE < privateKeyBytes.length) {
            // if privateKey.getD() is high, it will have 32 significant bytes and one signing byte (=0, because D is always positive)
            // thus we trim this signing byte to have an exactly 32 byte-long key
            return Arrays.copyOfRange(privateKeyBytes, 1, privateKeyBytes.length );

        } else if (privateKeyBytes.length < PRIVATE_KEY_SIZE) {
            // If privateKey.getD() is small enough, BigInteger#toByteArray() will return only 31 or less bytes
            // This is because BigInteger#toByteArray() generates the smallest byte array that can
            // represent the BigInteger, which means that on a 32-byte key, if the first bytes are `0`,
            // privateKey.getD().toByteArray() will trim them, so we re-insert them at the beginning of the byte array in order
            // to have a 32-byte key.
            int missingZeroByteNb = PRIVATE_KEY_SIZE - privateKeyBytes.length;

            byte[] formattedPrivateKeyBytes = new byte[PRIVATE_KEY_SIZE];
            Arrays.fill(formattedPrivateKeyBytes, 0, missingZeroByteNb - 1, (byte) 0);
            System.arraycopy(privateKeyBytes, 0, formattedPrivateKeyBytes, missingZeroByteNb, privateKeyBytes.length);

            return formattedPrivateKeyBytes;
        }
        else{
            return privateKeyBytes;
        }
    }

    /**
     * Decodes an hexadecimal string representing a private key
     * @param hexPrivateKey the hexadecimal-encoded private key (ONLY the integer)
     * @return the decoded private key
     */
    private static ECPrivateKey decodePrivateKey(String hexPrivateKey) {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(DEFAULT_CURVE_NAME);

        BigInteger d = new BigInteger(formatPrivateKey(HexString.decode(hexPrivateKey)));
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, params);

        try {
            return (ECPrivateKey) getKeyFactory().generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Decodes an hexadecimal string representing a public key
     * @param hexPublicKey the hexadecimal-encoded public key (ONLY the EC point coordinates)
     * @return the decoded public key
     */
    private static ECPublicKey decodePublicKey(String hexPublicKey) {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(DEFAULT_CURVE_NAME);

        ECPoint q = params.getCurve().decodePoint(HexString.decode(hexPublicKey));
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(q, params);

        try {
            return (ECPublicKey) getKeyFactory().generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Returns the BouncyCastle EC key factory
     * @return the BouncyCastle EC key factory
     */
    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(EC, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    /**
     * Performs the hexadecimal-encoding of the private key
     * @return the hexadecimal-encoded private key (contains ONLY the integer bytes)
     */
    public String encodePrivateKey() {
        return HexString.encode(formatPrivateKey(privateKey));
    }

    /**
     * Performs the hexadecimal-encoding of the public key
     * @return the hexadecimal-encoded public key (contains ONLY the compressed EC point coordinates)
     */
    public String encodePublicKey() {
        return HexString.encode(publicKey.getQ().getEncoded(true));
    }

    /**
     * Returns the private key
     * @return
     */
    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the formatted private key bytes
     * @return the formatted private key bytes (ONLY the integer bytes)
     */
    public byte[] getPrivateKeyBytes() {
        return formatPrivateKey(privateKey);
    }

    /**
     * Returns the formatted private key bytes
     * @return the formatted private key bytes (ONLY the compressed EC point coordinate bytes)
     */
    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Converts the 256-bit EC private key to a 256-bit AES secret key
     * @return the 256-bit AES secret key
     */
    public SecretKey convertToAESKey() {
        byte[] privateKey = formatPrivateKey(this.privateKey);
        return new SecretKeySpec(privateKey, AESEncryption.AES);
    }
}
