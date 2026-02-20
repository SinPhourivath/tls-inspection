package com.nbc.aet_pqc.service;

import com.nbc.aet_pqc.dto.TlsInspectResponse;
import com.nbc.aet_pqc.dto.TlsInspectResponse.CertificateDetail;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

@Service
public class TlsInspectionService {

    /**
     * Known post-quantum cryptographic identifiers found in cipher suites,
     * key exchange algorithm names, or named groups.
     */
    private static final Set<String> PQC_IDENTIFIERS = Set.of(
            "MLKEM", "ML-KEM", "X25519MLKEM768", "X25519MLKEM",
            "KYBER", "SIKE", "NTRU", "FRODOKEM", "FRODO",
            "BIKE", "HQC", "CLASSIC-MCELIECE",
            "DILITHIUM", "ML-DSA", "FALCON", "SPHINCS");

    public TlsInspectResponse inspect(String targetUrl) {
        String host;
        int port;

        try {
            URI uri = URI.create(targetUrl);
            host = uri.getHost();
            port = uri.getPort() == -1 ? 443 : uri.getPort();

            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Invalid URL: unable to extract host");
            }
        } catch (Exception e) {
            return errorResponse(targetUrl, "Invalid URL: " + e.getMessage());
        }

        try {
            SSLSocketFactory factory = createTrustAllSocketFactory();

            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                // Prefer TLS 1.3 but allow 1.2 fallback
                socket.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
                socket.setSoTimeout(10_000);

                socket.startHandshake();

                SSLSession session = socket.getSession();

                String tlsVersion = session.getProtocol();
                String cipherSuite = session.getCipherSuite();
                String keyExchange = extractKeyExchange(cipherSuite);

                List<CertificateDetail> certDetails = extractCertificates(session);

                boolean pqcDetected = detectPqc(cipherSuite, keyExchange);
                String pqcDetails = buildPqcDetails(cipherSuite, keyExchange, pqcDetected);

                return new TlsInspectResponse(
                        targetUrl,
                        tlsVersion,
                        cipherSuite,
                        keyExchange,
                        certDetails,
                        pqcDetected,
                        pqcDetails,
                        Instant.now().toString(),
                        null);
            }
        } catch (Exception e) {
            return errorResponse(targetUrl, "TLS handshake failed: " + e.getMessage());
        }
    }

    // ── Key exchange extraction ──────────────────────────────────────────

    private String extractKeyExchange(String cipherSuite) {
        if (cipherSuite == null)
            return "Unknown";

        // TLS 1.3 cipher suites (e.g. TLS_AES_256_GCM_SHA384) don't embed
        // the key exchange in the name — it's negotiated separately via
        // supported_groups / key_share extensions. Report what the JVM used.
        if (cipherSuite.startsWith("TLS_AES") || cipherSuite.startsWith("TLS_CHACHA")) {
            return detectTls13KeyExchange();
        }

        // TLS 1.2 cipher suites encode the key exchange in the name
        // e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        if (cipherSuite.contains("ECDHE"))
            return "ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)";
        if (cipherSuite.contains("DHE"))
            return "DHE (Diffie-Hellman Ephemeral)";
        if (cipherSuite.contains("ECDH"))
            return "ECDH (Elliptic Curve Diffie-Hellman)";
        if (cipherSuite.contains("DH"))
            return "DH (Diffie-Hellman)";
        if (cipherSuite.contains("RSA"))
            return "RSA";

        return "Unknown";
    }

    private String detectTls13KeyExchange() {
        // In TLS 1.3 on modern JDKs, the key exchange is determined by the
        // named group negotiated in the key_share extension. The standard
        // SSLSession API doesn't expose this directly, but we can query the
        // JVM's default named groups to indicate what was likely offered.
        // Put this before you create the SSLSocket (or at least before
        // startHandshake()).
        try {
            String namedGroups = System.getProperty("jdk.tls.namedGroups", "");
            if (!namedGroups.isBlank()) {
                return "TLS 1.3 key exchange (configured named groups: " + namedGroups + ")";
            }
        } catch (SecurityException _) {
            // ignore
        }
        return "TLS 1.3 key exchange (ECDHE / X25519 — default)";
    }

    // ── PQC detection ───────────────────────────────────────────────────

    private boolean detectPqc(String cipherSuite, String keyExchange) {
        String combined = (cipherSuite + " " + keyExchange).toUpperCase();
        return PQC_IDENTIFIERS.stream().anyMatch(combined::contains);
    }

    private String buildPqcDetails(String cipherSuite, String keyExchange, boolean detected) {
        if (!detected) {
            return "No post-quantum cryptographic mechanisms detected. "
                    + "The connection uses classical cryptography only.";
        }

        var sb = new StringBuilder("Post-quantum cryptography DETECTED. ");
        String combined = (cipherSuite + " " + keyExchange).toUpperCase();

        if (combined.contains("X25519MLKEM") || combined.contains("MLKEM")) {
            sb.append("ML-KEM (Module-Lattice Key Encapsulation) hybrid key exchange is in use. ");
            sb.append("This is a NIST-standardized post-quantum algorithm (FIPS 203). ");
        }
        if (combined.contains("KYBER")) {
            sb.append("CRYSTALS-Kyber key encapsulation detected (precursor to ML-KEM). ");
        }
        if (combined.contains("DILITHIUM") || combined.contains("ML-DSA")) {
            sb.append("ML-DSA (Dilithium) digital signature detected. ");
        }

        return sb.toString().trim();
    }

    // ── Certificate extraction ──────────────────────────────────────────

    private List<CertificateDetail> extractCertificates(SSLSession session) {
        List<CertificateDetail> details = new ArrayList<>();
        try {
            for (var cert : session.getPeerCertificates()) {
                if (cert instanceof X509Certificate x509) {
                    details.add(new CertificateDetail(
                            x509.getSubjectX500Principal().getName(),
                            x509.getIssuerX500Principal().getName(),
                            x509.getSerialNumber().toString(16),
                            x509.getSigAlgName(),
                            x509.getPublicKey().getAlgorithm(),
                            x509.getPublicKey().getEncoded().length * 8,
                            x509.getNotBefore().toInstant().toString(),
                            x509.getNotAfter().toInstant().toString()));
                }
            }
        } catch (SSLPeerUnverifiedException _) {
            // Peer certificates not available — return empty list
        }
        return details;
    }

    // ── Trust-all factory (inspection purposes only) ────────────────────

    private SSLSocketFactory createTrustAllSocketFactory()
            throws NoSuchAlgorithmException, KeyManagementException {

        TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {
                    }

                    @Override
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }
                }
        };

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, trustAll, new java.security.SecureRandom());
        return ctx.getSocketFactory();
    }

    // ── Error helper ────────────────────────────────────────────────────

    private TlsInspectResponse errorResponse(String url, String message) {
        return new TlsInspectResponse(
                url, null, null, null, List.of(),
                false, null, Instant.now().toString(), message);
    }
}
