package com.pdfscanner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDAdditionalActions;
import org.apache.pdfbox.pdmodel.interactive.action.PDDocumentCatalogAdditionalActions;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;

public class PDFSanitizer {

    public static boolean cleanPDF(File inputFile, File outputFile) {
        try (PDDocument document = PDDocument.load(inputFile)) {
            PDDocumentCatalog catalog = document.getDocumentCatalog();

            // Remove JavaScript from OpenAction
            if (catalog.getOpenAction() instanceof PDActionJavaScript) {
                catalog.setOpenAction(null);
            }

            // Remove JavaScript name tree using reflection
            if (catalog.getNames() != null) {
                try {
                    Field jsField = catalog.getNames().getClass().getDeclaredField("javaScript");
                    jsField.setAccessible(true);
                    jsField.set(catalog.getNames(), null);
                } catch (NoSuchFieldException | IllegalAccessException e) {
                    System.err.println("Could not clear JavaScript name tree: " + e.getMessage());
                }
            }

            // Remove document-level additional actions
            PDDocumentCatalogAdditionalActions actions = catalog.getActions();
            if (actions != null) {
                catalog.setActions(null);
            }

            document.save(outputFile);
            return true;

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}
