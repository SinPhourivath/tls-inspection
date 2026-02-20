package com.nbc.aet_pqc.service;

import com.nbc.aet_pqc.dto.TlsInspectResponse;
import com.nbc.aet_pqc.dto.TlsInspectResponse.CertificateDetail;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class TlsInspectionService {

    private static final Logger log = LoggerFactory.getLogger(TlsInspectionService.class);

    /**
     * Known post-quantum cryptographic identifiers found in cipher suites,
     * key exchange algorithm names, or named groups.
     */
    private static final Set<String> PQC_IDENTIFIERS = Set.of(
            "MLKEM", "ML-KEM", "X25519MLKEM768", "X25519MLKEM",
            "KYBER", "SIKE", "NTRU", "FRODOKEM", "FRODO",
            "BIKE", "HQC", "CLASSIC-MCELIECE",
            "DILITHIUM", "ML-DSA", "FALCON", "SPHINCS");

    /**
     * Named groups advertised to the server in order of preference.
     * X25519MLKEM768 is the hybrid PQC group (NIST ML-KEM + X25519).
     * Requires OpenSSL 3.2+.
     */
    private static final String NAMED_GROUPS = "X25519MLKEM768:x25519:P-256:P-384";

    // ── Startup check ────────────────────────────────────────────────────

    @PostConstruct
    public void checkOpenSslVersion() {
        try {
            Process p = new ProcessBuilder("openssl", "version")
                    .redirectErrorStream(true)
                    .start();
            String version = new String(p.getInputStream().readAllBytes()).trim();
            log.info("OpenSSL available: {}", version);

            // Warn if version is below 3.2 (required for X25519MLKEM768 support)
            if (!version.isBlank()) {
                Matcher m = Pattern.compile("OpenSSL (\\d+)\\.(\\d+)").matcher(version);
                if (m.find()) {
                    int major = Integer.parseInt(m.group(1));
                    int minor = Integer.parseInt(m.group(2));
                    if (major < 3 || (major == 3 && minor < 2)) {
                        log.warn(
                                "OpenSSL {} detected — version 3.2+ is required for X25519MLKEM768 (hybrid PQC) support. "
                                        +
                                        "PQC detection may not work correctly.",
                                version);
                    }
                }
            }
        } catch (Exception e) {
            throw new IllegalStateException(
                    "OpenSSL not found on PATH — required for TLS inspection. " +
                            "Please install OpenSSL 3.2+ and ensure it is available on the system PATH.",
                    e);
        }
    }

    // ── Main inspection entry point ──────────────────────────────────────

    public TlsInspectResponse inspect(String targetUrl) {
        String host;
        int port;

        try {
            URI uri = URI.create(targetUrl);
            host = uri.getHost();
            port = uri.getPort() == -1 ? 443 : uri.getPort();

            if (host == null || host.isBlank()) {
                throw new IllegalArgumentException("Unable to extract host");
            }
        } catch (Exception e) {
            return errorResponse(targetUrl, "Invalid URL: " + e.getMessage());
        }

        try {
            String opensslOutput = runOpenSslHandshake(host, port);
            List<CertificateDetail> certs = fetchCertificates(host, port);
            return parseOpenSslOutput(targetUrl, opensslOutput, certs);
        } catch (Exception e) {
            return errorResponse(targetUrl, "Inspection failed: " + e.getMessage());
        }
    }

    // ── OpenSSL subprocess handshake ─────────────────────────────────────

    /**
     * Runs {@code openssl s_client} with PQC-capable named groups and
     * returns its combined stdout+stderr output.
     *
     * <p>
     * The {@code -brief} flag suppresses verbose certificate PEM output.
     * {@code -no_ign_eof} ensures openssl exits once stdin is closed.
     */
    private String runOpenSslHandshake(String host, int port) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
                "openssl", "s_client",
                "-connect", host + ":" + port,
                "-groups", NAMED_GROUPS,
                "-brief",
                "-no_ign_eof");
        pb.redirectErrorStream(true);

        Process proc = pb.start();
        // Close stdin immediately so openssl does not wait for user input
        proc.getOutputStream().close();

        boolean finished = proc.waitFor(10, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            throw new RuntimeException("OpenSSL handshake timed out after 10 seconds");
        }

        return new String(proc.getInputStream().readAllBytes());
    }

    // ── Output parsing ────────────────────────────────────────────────────

    private TlsInspectResponse parseOpenSslOutput(
            String url, String output, List<CertificateDetail> certs) {

        String tlsVersion = extractField(output, "Protocol version:\\s*(\\S+)");
        String cipherSuite = extractField(output, "Ciphersuite:\\s*(\\S+)");

        // TLS 1.3: "Negotiated TLS1.3 group: X25519MLKEM768"
        // TLS 1.2: "Server Temp Key: ECDH, P-256, 256 bits"
        String negotiatedGroup = extractField(output, "Negotiated TLS1\\.3 group:\\s*(\\S+)");
        String serverTempKey = extractField(output, "Server Temp Key:\\s*(.+)");
        String keyExchange = negotiatedGroup != null ? negotiatedGroup
                : serverTempKey != null ? serverTempKey
                        : resolveKeyExchange(cipherSuite);

        boolean pqcDetected = isPqc(cipherSuite, keyExchange);
        String pqcDetails = buildPqcDetails(cipherSuite, keyExchange, pqcDetected);

        if (tlsVersion == null && cipherSuite == null) {
            return errorResponse(url, "TLS handshake failed or produced no output. Raw output: " + output.trim());
        }

        return new TlsInspectResponse(
                url,
                tlsVersion,
                cipherSuite,
                keyExchange,
                certs,
                pqcDetected,
                pqcDetails,
                Instant.now().toString(),
                null);
    }

    private String extractField(String text, String pattern) {
        Matcher m = Pattern.compile(pattern, Pattern.MULTILINE).matcher(text);
        return m.find() ? m.group(1).trim() : null;
    }

    // ── Key exchange helpers ─────────────────────────────────────────────

    /**
     * Fallback for TLS 1.2 cipher suites where the key exchange is encoded
     * in the cipher name (e.g. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384).
     * For TLS 1.3, the Server Temp Key line is the authoritative source.
     */
    private String resolveKeyExchange(String cipherSuite) {
        if (cipherSuite == null)
            return "Unknown";
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

    // ── PQC detection ────────────────────────────────────────────────────

    private boolean isPqc(String cipherSuite, String keyExchange) {
        String combined = ((cipherSuite != null ? cipherSuite : "") + " "
                + (keyExchange != null ? keyExchange : "")).toUpperCase();
        return PQC_IDENTIFIERS.stream().anyMatch(combined::contains);
    }

    private String buildPqcDetails(String cipherSuite, String keyExchange, boolean detected) {
        if (!detected) {
            return "No post-quantum cryptographic mechanisms detected. "
                    + "The connection uses classical cryptography only.";
        }

        StringBuilder sb = new StringBuilder("Post-quantum cryptography DETECTED. ");
        String combined = ((cipherSuite != null ? cipherSuite : "") + " "
                + (keyExchange != null ? keyExchange : "")).toUpperCase();

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
        if (combined.contains("FALCON")) {
            sb.append("Falcon digital signature detected. ");
        }
        if (combined.contains("SPHINCS")) {
            sb.append("SPHINCS+ digital signature detected. ");
        }

        return sb.toString().trim();
    }

    // ── Certificate extraction (Java SSLSocket) ───────────────────────────

    /**
     * Fetches the peer certificate chain using a trust-all SSLSocket.
     * This is kept separate from the OpenSSL handshake because parsing PEM
     * from OpenSSL's stdout is fragile. The SSLSession API is cleaner for
     * structured certificate data.
     */
    private List<CertificateDetail> fetchCertificates(String host, int port) {
        try {
            SSLSocketFactory factory = createTrustAllSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setEnabledProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
                socket.setSoTimeout(10_000);
                socket.startHandshake();
                return extractCertificates(socket.getSession());
            }
        } catch (Exception e) {
            log.warn("Could not fetch certificates for {}:{} — {}", host, port, e.getMessage());
            return List.of();
        }
    }

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
        } catch (SSLPeerUnverifiedException e) {
            log.warn("Peer certificates not available: {}", e.getMessage());
        }
        return details;
    }

    // ── Trust-all factory (inspection purposes only) ─────────────────────

    private SSLSocketFactory createTrustAllSocketFactory()
            throws NoSuchAlgorithmException, KeyManagementException {

        TrustManager[] trustAll = new TrustManager[] {
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] c, String a) {
                    }

                    @Override
                    public void checkServerTrusted(X509Certificate[] c, String a) {
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

    // ── Error helper ─────────────────────────────────────────────────────

    private TlsInspectResponse errorResponse(String url, String message) {
        return new TlsInspectResponse(
                url, null, null, null, List.of(),
                false, null, Instant.now().toString(), message);
    }
}
