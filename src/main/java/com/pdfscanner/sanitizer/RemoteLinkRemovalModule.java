package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;
public class RemoteLinkRemovalModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        for (org.apache.pdfbox.pdmodel.PDPage page : document.getPages()) {
            try {
                java.util.List<org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation> annotations = page.getAnnotations();
                annotations.removeIf(ann ->
                        "Link".equals(ann.getSubtype()) &&
                                ann.getCOSObject().toString().contains("/URI")
                );
            } catch (java.io.IOException e) {
                System.err.println("Failed to get annotations: " + e.getMessage());
            }
        }
        System.out.println("Removed remote link annotations.");
    }
}
