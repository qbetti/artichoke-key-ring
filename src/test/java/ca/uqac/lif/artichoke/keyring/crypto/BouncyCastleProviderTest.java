package ca.uqac.lif.artichoke.keyring.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Provider;
import java.security.Security;

import static org.junit.Assert.*;


public class BouncyCastleProviderTest {

    @BeforeClass
    public static void addProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testProvider() {
        Provider provider = Security.getProvider("BC");
        assertNotNull(provider);

        assertTrue(provider instanceof BouncyCastleProvider);
    }

}
