import java.security.KeyPair;
import java.security.KeyPairGenerator;

public class EdKeyGeneration {
    private static final String ED_NAME = "Ed448";

    KeyPair ed25519() throws Exception {
        return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    KeyPair ed448() throws Exception {
        return KeyPairGenerator.getInstance("Ed448").generateKeyPair();
    }

    KeyPair generic() throws Exception {
        return KeyPairGenerator.getInstance("EdDSA").generateKeyPair();
    }

    KeyPair constant() throws Exception {
        return KeyPairGenerator.getInstance(ED_NAME).generateKeyPair();
    }

    KeyPair exchange() throws Exception {
        return KeyPairGenerator.getInstance("XDH").generateKeyPair();
    }

    KeyPair unresolved(String name) throws Exception {
        return KeyPairGenerator.getInstance(name).generateKeyPair();
    }
}
