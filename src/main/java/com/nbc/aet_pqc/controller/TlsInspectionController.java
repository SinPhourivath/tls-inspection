package com.nbc.aet_pqc.controller;

import com.nbc.aet_pqc.dto.TlsInspectRequest;
import com.nbc.aet_pqc.dto.TlsInspectResponse;
import com.nbc.aet_pqc.service.TlsInspectionService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/tls")
public class TlsInspectionController {

    private final TlsInspectionService inspectionService;

    public TlsInspectionController(TlsInspectionService inspectionService) {
        this.inspectionService = inspectionService;
    }

    @PostMapping("/inspect")
    public ResponseEntity<TlsInspectResponse> inspect(@Valid @RequestBody TlsInspectRequest request) {
        TlsInspectResponse response = inspectionService.inspect(request.url());
        return ResponseEntity.ok(response);
    }
}
