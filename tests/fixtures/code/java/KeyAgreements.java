import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.KEM;
import javax.crypto.KeyAgreement;

class KeyAgreements {
    void ecdh() throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        KeyAgreement xdh = KeyAgreement.getInstance("XDH");
        KeyAgreement dh = KeyAgreement.getInstance("DiffieHellman");
    }

    void ecKey() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
    }

    void ecKeyBare() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
    }

    void specOnly() throws Exception {
        ECGenParameterSpec spec = new ECGenParameterSpec("secp384r1");
    }

    void finiteField() throws Exception {
        KeyPairGenerator dh = KeyPairGenerator.getInstance("DH");
        dh.initialize(2048);
        KeyPairGenerator dsa = KeyPairGenerator.getInstance("DSA");
        dsa.initialize(1024);
    }

    void postQuantum() throws Exception {
        KEM kem = KEM.getInstance("ML-KEM-768");
        KeyPairGenerator sig = KeyPairGenerator.getInstance("ML-DSA-65");
        Signature s = Signature.getInstance("ML-DSA");
    }

    void ecdsaSignature() throws Exception {
        Signature s = Signature.getInstance("SHA256withECDSA");
    }
}
