package com.pdfscanner;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.text.PDFTextStripper;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDAdditionalActions;




import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class PDFScanner {
    private static final List<String> MALICIOUS_KEYWORDS = Arrays.asList(
            "malware", "exploit", "virus", "trojan", "payload", "attack",
            "cmd.exe", "powershell", "shellcode", "javascript:", "autoopen",
            "/js", "launch", "exec", "vbs", "obfuscate", "document.write",
            "activexobject", "wscript.shell"
    );

    private static final List<Pattern> MALICIOUS_REGEX = Arrays.asList(
            Pattern.compile("eval\\s*\\(", Pattern.CASE_INSENSITIVE),
            Pattern.compile("new\\s+Function", Pattern.CASE_INSENSITIVE),
            Pattern.compile("base64\\s*decode", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("Shell\\.Application", Pattern.CASE_INSENSITIVE)
    );

    private int keywordScore(String text) {
        int score = 0;
        for (String keyword : MALICIOUS_KEYWORDS) {
            if (text.contains(keyword)) {
                score += 1;
            }
        }
        return score;
    }

    private int regexScore(String text) {
        int score = 0;
        for (Pattern pattern : MALICIOUS_REGEX) {
            if (pattern.matcher(text).find()) {
                score += 2;
            }
        }
        return score;
    }

    private int javascriptScore(PDDocument document) {
        int score = 0;
        PDDocumentCatalog catalog = document.getDocumentCatalog();

        // 1. Check for JavaScript in OpenAction (some PDFs have JS set here)
        try {
            if (catalog.getOpenAction() instanceof PDActionJavaScript) {
                PDActionJavaScript jsAction = (PDActionJavaScript) catalog.getOpenAction();
                String jsCode = jsAction.getAction();
                score += analyzeJavaScript(jsCode);
            }
        } catch (Exception e) {
            System.err.println("Error checking open action JS: " + e.getMessage());
        }

        // 2. Check for JavaScript in document-level JavaScript name tree
        try {
            if (catalog.getNames() != null && catalog.getNames().getJavaScript() != null) {
                for (PDActionJavaScript js : catalog.getNames().getJavaScript().getNames().values()) {
                    score += analyzeJavaScript(js.getAction());
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking document JavaScript names: " + e.getMessage());
        }

        return score;
    }



    private int analyzeJavaScript(String jsCode) {
        if (jsCode == null) return 0;

        int score = 0;
        String lowerJS = jsCode.toLowerCase();

        List<String> suspiciousJSKeywords = Arrays.asList(
                "eval", "document.write", "app.alert", "util.printf",
                "this.exportdataobject", "collab.geticon", "this.getfield"
        );

        for (String keyword : suspiciousJSKeywords) {
            if (lowerJS.contains(keyword)) {
                score += 3; // suspicious javascript keyword found
            }
        }
        return score;
    }

    public ScanResult scan(File pdfFile) throws IOException {
        int totalScore = 0;
        try (PDDocument document = PDDocument.load(pdfFile)) {
            PDFTextStripper stripper = new PDFTextStripper();
            String text = stripper.getText(document).toLowerCase();

            totalScore += keywordScore(text);
            totalScore += regexScore(text);
            totalScore += javascriptScore(document);
        }

        String classification;
        boolean maliciousFlag;
        if (totalScore > 5) {
            classification = "Malicious";
            maliciousFlag = true;
        } else if (totalScore >= 3) {
            classification = "Suspicious";
            maliciousFlag = false;
        } else {
            classification = "Clean";
            maliciousFlag = false;
        }

        return new ScanResult(pdfFile.getName(), maliciousFlag, classification, totalScore);
    }
}
