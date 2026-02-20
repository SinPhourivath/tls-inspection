package com.nbc.aet_pqc.dto;

import jakarta.validation.constraints.NotBlank;

public record TlsInspectRequest(
        @NotBlank(message = "URL is required") String url) {
}
