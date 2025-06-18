package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;

public class JavaScriptRemovalModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        PDDocumentCatalog catalog = document.getDocumentCatalog();
        try {
            Object openAction = catalog.getOpenAction();
            if (openAction instanceof PDActionJavaScript) {
                catalog.setOpenAction(null);
                System.out.println("JavaScript action removed.");
            }
        } catch (java.io.IOException e) {
            System.err.println("Failed to access OpenAction: " + e.getMessage());
        }
    }
}
