import javax.net.ssl.SSLContext;

public final class TlsVersions {

    private static final String LEGACY = "TLSv1.1";

    static SSLContext tls10() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }

    static SSLContext tls11() throws Exception {
        return SSLContext.getInstance(LEGACY);
    }

    static SSLContext ssl3() throws Exception {
        return SSLContext.getInstance("SSLv3", "SunJSSE");
    }

    static SSLContext modern() throws Exception {
        return SSLContext.getInstance("TLSv1.2");
    }

    static SSLContext negotiated() throws Exception {
        return SSLContext.getInstance("TLS");
    }

    static SSLContext fromParameter(String protocol) throws Exception {
        return SSLContext.getInstance(protocol);
    }
}
