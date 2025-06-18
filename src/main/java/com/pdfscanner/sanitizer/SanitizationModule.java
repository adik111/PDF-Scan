package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;

public interface SanitizationModule {
    void sanitize(PDDocument document);
}
