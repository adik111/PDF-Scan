package com.pdfscanner;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.text.PDFTextStripper;

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

        try {
            if (catalog.getOpenAction() instanceof PDActionJavaScript) {
                PDActionJavaScript jsAction = (PDActionJavaScript) catalog.getOpenAction();
                String jsCode = jsAction.getAction();
                score += analyzeJavaScript(jsCode);
            }
        } catch (Exception e) {
            System.err.println("Error checking open action JS: " + e.getMessage());
        }

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
                score += 3;
            }
        }
        return score;
    }

    private int embeddedFileScore(PDDocument document) {
        try {
            if (document.getDocumentCatalog().getNames() != null &&
                    document.getDocumentCatalog().getNames().getEmbeddedFiles() != null) {
                return 5;
            }
        } catch (Exception e) {
            System.err.println("Error checking embedded files: " + e.getMessage());
        }
        return 0;
    }

    private int linkScore(String text) {
        int score = 0;
        if (text.contains("http://") || text.contains("https://")) {
            if (text.contains("bit.ly") || text.contains("tinyurl") || text.contains("discord.gg")) {
                score += 2;
            }
            if (text.matches(".*://[^\\s]*\\.exe")) {
                score += 4;
            }
        }
        return score;
    }

    private int obfuscationScore(String text) {
        int score = 0;
        if (text.matches(".*([A-Za-z0-9+/]{100,}).*")) {
            score += 2;
        }
        if (text.matches(".*\\\\x[0-9A-Fa-f]{2}.*")) {
            score += 2;
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
            totalScore += embeddedFileScore(document);
            totalScore += linkScore(text);
            totalScore += obfuscationScore(text);
        }

        String classification;
        boolean maliciousFlag;

        if (totalScore >= 6) {
            classification = "Malicious";
            maliciousFlag = true;
        } else if (totalScore >= 4) {
            classification = "Suspicious";
            maliciousFlag = false;
        } else {
            classification = "Clean";
            maliciousFlag = false;
        }

        return new ScanResult(pdfFile.getName(), maliciousFlag, classification, totalScore);
    }
}
