package com.nbc.aet_pqc.dto;

import java.util.List;

public record TlsInspectResponse(
        String url,
        String tlsVersion,
        String cipherSuite,
        String keyExchangeAlgorithm,
        List<CertificateDetail> peerCertificates,
        boolean pqcDetected,
        String pqcDetails,
        String inspectedAt,
        String error) {

    public record CertificateDetail(
            String subject,
            String issuer,
            String serialNumber,
            String signatureAlgorithm,
            String publicKeyAlgorithm,
            int publicKeySize,
            String validFrom,
            String validTo) {
    }
}
