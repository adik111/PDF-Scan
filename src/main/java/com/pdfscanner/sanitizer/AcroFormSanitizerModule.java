package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;

public class AcroFormSanitizerModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm acroForm = document.getDocumentCatalog().getAcroForm();
        if (acroForm != null) {
            acroForm.getFields().clear();
            document.getDocumentCatalog().setAcroForm(null);
            System.out.println("Removed AcroForm fields.");
        }
    }
}
