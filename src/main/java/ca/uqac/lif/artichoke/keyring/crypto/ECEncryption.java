package ca.uqac.lif.artichoke.keyring.crypto;

import ca.uqac.lif.artichoke.keyring.HexString;
import com.sun.istack.internal.NotNull;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.*;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class ECEncryption {

    public static final String EC = "EC";
    private static final String SIGNATURE_ALGO = "SHA1withECDSA";
    private static final String DEFAULT_CURVE_NAME = "secp256k1";
    public static final int PRIVATE_KEY_SIZE = 32; // in bytes

    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;

    public ECEncryption(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = (ECPrivateKey) privateKey;
        this.publicKey = (ECPublicKey) publicKey;
    }

    public ECEncryption(String hexPrivateKey, String hexPublicKey) {
        this(retrievePrivateKey(hexPrivateKey), retrievePublicKey(hexPublicKey));
    }

    public ECEncryption(KeyPair keyPair) {
        this(keyPair.getPrivate(), keyPair.getPublic());
    }

    public ECEncryption() {
        this(generateNewKeys());
    }

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


    public byte[] sign(byte[] data) {
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
            return ecdsa.sign();
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

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


    private static byte[] trimSigningByte(ECPrivateKey privateKey) {
        return trimSigningByte(privateKey.getD().toByteArray());
    }

    private static byte[] trimSigningByte(byte[] privateKeyBytes) {
        if(PRIVATE_KEY_SIZE < privateKeyBytes.length) {
            //
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

    private static ECPrivateKey retrievePrivateKey(String hexPrivateKey) {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(DEFAULT_CURVE_NAME);

        BigInteger d = new BigInteger(trimSigningByte(HexString.decode(hexPrivateKey)));
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, params);

        try {
            return (ECPrivateKey) getKeyFactory().generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static ECPublicKey retrievePublicKey(String hexPublicKey) {
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

    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(EC, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    public String encodePrivateKey() {
        return HexString.encode(trimSigningByte(privateKey));
    }

    public String encodePublicKey() {
        return HexString.encode(publicKey.getQ().getEncoded(true));
    }

    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    public SecretKey convertToAESKey() {
        byte[] privateKey = trimSigningByte(this.privateKey);
        return new SecretKeySpec(privateKey, AESEncryption.AES);
    }
}
