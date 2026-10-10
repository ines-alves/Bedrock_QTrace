import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public final class Signatures {

    private static final int RSA_BITS = 2048;

    static KeyPair rsaPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(RSA_BITS);
        return generator.generateKeyPair();
    }

    static byte[] sign(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    static boolean verify(PublicKey publicKey, byte[] message, byte[] sig) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(message);
        return signature.verify(sig);
    }

    static byte[] signWithImportedKey(PrivateKey importedKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(importedKey);
        signature.update(message);
        return signature.sign();
    }

    static KeyPair edPair() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static byte[] signEd(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    static byte[] signEcdsa(PrivateKey privateKey, byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(message);
        return signature.sign();
    }

    static boolean run() throws Exception {
        KeyPair pair = rsaPair();
        byte[] sig = sign(pair.getPrivate(), new byte[0]);
        return verify(pair.getPublic(), new byte[0], sig);
    }
}
