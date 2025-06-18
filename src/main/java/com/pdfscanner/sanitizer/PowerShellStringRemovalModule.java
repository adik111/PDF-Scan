package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDStream;

import java.io.IOException;
import java.io.OutputStream;
import java.util.List;
import java.util.regex.Pattern;

public class PowerShellStringRemovalModule implements SanitizationModule {

    private static final List<Pattern> SUSPICIOUS_PATTERNS = List.of(
            Pattern.compile("powershell", Pattern.CASE_INSENSITIVE),
            Pattern.compile("cmd\\.exe", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wscript\\.shell", Pattern.CASE_INSENSITIVE),
            Pattern.compile("shell\\.application", Pattern.CASE_INSENSITIVE),
            Pattern.compile("invoke-expression", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public void sanitize(PDDocument document) {
        try {
            PDFTextStripper stripper = new PDFTextStripper();

            for (int i = 0; i < document.getNumberOfPages(); i++) {
                PDPage page = document.getPage(i);
                String text = stripper.getText(document);

                boolean hasMaliciousText = SUSPICIOUS_PATTERNS.stream()
                        .anyMatch(pattern -> pattern.matcher(text).find());

                if (hasMaliciousText) {
                    // Replace stream content with a warning
                    PDStream emptyStream = new PDStream(document);
                    try (OutputStream out = emptyStream.createOutputStream()) {
                        out.write("This page contained potentially malicious script content and has been sanitized.".getBytes());
                    }
                    page.setContents(emptyStream);
                    System.out.println("PowerShell-like content sanitized on page " + (i + 1));
                }
            }

        } catch (IOException e) {
            System.err.println("Error scanning for PowerShell strings: " + e.getMessage());
        }
    }
}
