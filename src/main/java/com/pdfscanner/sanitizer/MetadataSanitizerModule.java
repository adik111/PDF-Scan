package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;

public class MetadataSanitizerModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        document.getDocumentInformation().getCOSObject().clear();
        document.getDocumentCatalog().setMetadata(null);
        System.out.println("Cleared metadata.");
    }
}
