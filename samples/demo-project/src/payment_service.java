// Deliberately weak sample for the Periperi demo. Never use in production.

import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class PaymentService {

    static {
        java.security.Security.addProvider(new BouncyCastleProvider());
    }

    /** 1024-bit RSA is factorable and must be replaced. */
    public static KeyPairGenerator weakRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "BC");
        generator.initialize(1024);
        return generator;
    }

    /** DES in ECB mode for legacy stored tokens. */
    public static byte[] encryptToken(String secretKey, byte[] payload) throws Exception {
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(
                secretKey.getBytes("UTF-8"), "DES"));
        return cipher.doFinal(payload);
    }

    /** SHA1withRSA signature for statement PDFs. */
    public static byte[] signStatement(byte[] statement, java.security.PrivateKey key)
            throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(key);
        signature.update(statement);
        return signature.sign();
    }

    /** Card PAN is encrypted with a key held by the payment HSM via PKCS#11. */
    public static String panCipherSuite() {
        return "PKCS#11 RSA-1024-CBC via hardware security module";
    }
}
