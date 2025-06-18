package com.pdfscanner.sanitizer;

import java.io.IOException;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;

public class LaunchActionRemovalModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        PDDocumentCatalog catalog = document.getDocumentCatalog();
        Object openActionObj;
        try {
            openActionObj = catalog.getOpenAction();
            if (openActionObj instanceof PDActionLaunch) {
                catalog.setOpenAction(null);
                System.out.println("Launch action removed.");
            }
        } catch (IOException e) {
            System.err.println("Failed to get OpenAction: " + e.getMessage());
        }
    }
}
