package com.pdfscanner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

public class PDFScanner {
    private static final List<String> MALICIOUS_KEYWORDS = Arrays.asList(
            "malware", "exploit", "virus", "trojan", "payload", "attack"
    );

    public boolean scan(File pdfFile) throws IOException {
        try (PDDocument document = PDDocument.load(pdfFile)) {
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document).toLowerCase();

            for (String keyword : MALICIOUS_KEYWORDS) {
                if (text.contains(keyword)) {
                    return true; // Malicious keyword found
                }
            }
        }
        return false; // No keywords found
    }
}

