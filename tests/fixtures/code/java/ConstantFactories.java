import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;

class ConstantFactories {
    private static final String DIGEST = "SHA-1";
    private static final String MAC_ALGO = "HmacSHA256";
    private static final String KDF = "PBKDF2WithHmacSHA1";
    private static final String KEY_ALGO = "RSA";
    private static final String SIG = "SHA256withRSA";
    private static final String EDSIG = "Ed25519";
    private static final String AGREE = "ECDH";
    private static final String CIPHER_ALGO = "AES";

    void use(String external) throws Exception {
        MessageDigest md = MessageDigest.getInstance(DIGEST);
        Mac mac = Mac.getInstance(MAC_ALGO);
        SecretKeyFactory f = SecretKeyFactory.getInstance(KDF);
        KeyPairGenerator g = KeyPairGenerator.getInstance(KEY_ALGO);
        g.initialize(1024);
        Signature s = Signature.getInstance(SIG);
        Signature e = Signature.getInstance(EDSIG);
        KeyAgreement a = KeyAgreement.getInstance(AGREE);
        KeyGenerator k = KeyGenerator.getInstance(CIPHER_ALGO);
        k.init(128);
        MessageDigest unknown = MessageDigest.getInstance(external);
        KeyAgreement other = KeyAgreement.getInstance(external);
    }
}
