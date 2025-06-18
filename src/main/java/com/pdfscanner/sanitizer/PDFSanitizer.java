package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.File;
import java.io.IOException;

public class PDFSanitizer {

    public static boolean cleanPDF(File inputFile, File outputFile) {
        try (PDDocument document = PDDocument.load(inputFile)) {
            Sanitizer sanitizer = new Sanitizer();
            sanitizer.sanitize(document);
            document.save(outputFile);
            return true;
        } catch (IOException e) {
            System.err.println("Error sanitizing PDF: " + e.getMessage());
            return false;
        }
    }
}
