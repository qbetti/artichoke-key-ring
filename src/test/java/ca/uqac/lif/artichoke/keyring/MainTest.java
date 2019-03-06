package ca.uqac.lif.artichoke.keyring;

import org.bouncycastle.crypto.generators.SCrypt;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


public class MainTest {


    private static final String CURVE_NAME = "secp256k1";

    @Test
    public void ECtest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        Security.addProvider(new BouncyCastleProvider());

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec(CURVE_NAME));
        KeyPair keyPair = gen.generateKeyPair();

        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        byte[] s = privateKey.getD().toByteArray();
        byte[] actualPrivateKey = new byte[32];

        if(s.length >= 32 && s[0] == 0) {
            actualPrivateKey = Arrays.copyOfRange(s, 1, s.length);
        } else {
            actualPrivateKey = s;
        }
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(CURVE_NAME);
        KeyFactory kf = KeyFactory.getInstance("EC", "BC");

        String hexPrivateKey = new String(Hex.encode(actualPrivateKey));
        String hexPublicKey = new String(Hex.encode(publicKey.getQ().getEncoded(true)));

        Signature ecdsa = Signature.getInstance("SHA1withECDSA");
        ecdsa.initSign(kf.generatePrivate(new ECPrivateKeySpec(new BigInteger(actualPrivateKey),  params)));
        String data = "lol";
        ecdsa.update(data.getBytes());
        byte[] signature = ecdsa.sign();


        ECPoint q = params.getCurve().decodePoint(Hex.decode(hexPublicKey));
        BigInteger d = new BigInteger(Hex.decode(hexPrivateKey));

        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(q, params);

        PublicKey pKey = kf.generatePublic(publicKeySpec);


        Signature ecdsa2 = Signature.getInstance("SHA1withECDSA");
        ecdsa2.initVerify(pKey);
        ecdsa2.update(data.getBytes());
        boolean result = ecdsa2.verify(signature);

        System.out.println(result);

        // SCRYPT

        String password = "mdp";

        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[32];
        random.nextBytes(salt);


        byte[] derivedKey = SCrypt.generate(password.getBytes(), salt, 262144, 8, 1, 32);
        String encodedDerivedKey = new String(Hex.encode(derivedKey));
//        System.out.println("DK: " + encodedDerivedKey);

        byte[] iv = new byte[16];
        SecureRandom random0 = new SecureRandom();
        random0.nextBytes(iv);
        String encodedIv = new String(Hex.encode(iv));
        System.out.println("IV: " + encodedIv);

        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derivedKey, "AES"), ivParameterSpec);

        byte[] encryptedPrivateKey = cipher.doFinal(actualPrivateKey);
        String hexEncryptedPrivateKey = new String(Hex.encode(encryptedPrivateKey));
        System.out.println("HEX enc private key: " + hexEncryptedPrivateKey);


        Cipher cipher1 = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        cipher1.init(Cipher.DECRYPT_MODE, new SecretKeySpec(Hex.decode(encodedDerivedKey), "AES"), new IvParameterSpec(Hex.decode(encodedIv)));

        byte[] secretKey0 = cipher1.doFinal(Hex.decode(hexEncryptedPrivateKey));

        Assert.assertArrayEquals(secretKey0, actualPrivateKey);

        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(new BigInteger(secretKey0), params);
        PrivateKey sKey = kf.generatePrivate(privateKeySpec);

        Signature ecdsa3 = Signature.getInstance("SHA1withECDSA");
        ecdsa.initSign(sKey);
        ecdsa.update(data.getBytes());
        byte[] signature3 = ecdsa.sign();

        ecdsa3.initVerify(publicKey);
        ecdsa3.update(data.getBytes());

        boolean result2 = ecdsa3.verify(signature3);

        Assert.assertTrue(result2);

        KeyGenerator generator = KeyGenerator.getInstance("AES", "BC");
        generator.init(256);
        SecretKey secretKey = generator.generateKey();
        String hexSecretKey = new String(Hex.encode(secretKey.getEncoded()));
        System.out.println(secretKey.getEncoded().length);
        System.out.println("hexGroupSecrectKey:" + hexSecretKey);


        SecureRandom random1 = new SecureRandom();
        random1.nextBytes(iv);
        System.out.println("iv: "+ new String(Hex.encode(iv)));

//        System.out.println( privateKey.getD().toByteArray().length);
//        System.out.println(new String(Hex.encode(privateKey.getD().toByteArray())));

        Cipher cipher2 = Cipher.getInstance("AES/CTR/NoPadding", "BC");
        cipher2.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(actualPrivateKey, "AES"), new IvParameterSpec(iv));

        byte[] encGroupKey = cipher2.doFinal(secretKey.getEncoded());
        System.out.println(new String(Hex.encode(encGroupKey)));

        cipher2.init(Cipher.DECRYPT_MODE, new SecretKeySpec(actualPrivateKey, "AES"), new IvParameterSpec(iv));
        byte[] decGroupKey = cipher2.doFinal(encGroupKey);

        System.out.println("decodedGroupKey:"+ new String(Hex.encode(decGroupKey)));
    }

}