package com.pdfscanner;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDDocumentInformation;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.common.PDMetadata;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionFactory;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.outline.PDDocumentOutline;
import org.apache.pdfbox.pdmodel.interactive.documentnavigation.outline.PDOutlineItem;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
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
            Pattern.compile("Shell\\.Application", Pattern.CASE_INSENSITIVE),
            Pattern.compile("powershell", Pattern.CASE_INSENSITIVE),
            Pattern.compile("wscript\\.shell", Pattern.CASE_INSENSITIVE)
    );

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
            totalScore += formFieldScore(document);
            totalScore += metadataScore(document);
            totalScore += launchActionScore(document);
            totalScore += bookmarkActionScore(document);
            totalScore += annotationScore(document);
        }

        String classification;
        boolean maliciousFlag;

        if (totalScore >= 4) {
            classification = "Malicious";
            maliciousFlag = true;
        } else if (totalScore >= 2) {
            classification = "Suspicious";
            maliciousFlag = false;
        } else {
            classification = "Clean";
            maliciousFlag = false;
        }

        return new ScanResult(pdfFile.getName(), maliciousFlag, classification, totalScore);
    }

    private int keywordScore(String text) {
        int score = 0;
        for (String keyword : MALICIOUS_KEYWORDS) {
            if (text.contains(keyword)) {
                score++;
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

        try {
            COSBase openActionBase = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.OPEN_ACTION);
            if (openActionBase instanceof COSDictionary) {
                PDAction openAction = PDActionFactory.createAction((COSDictionary) openActionBase);
                if (openAction instanceof PDActionJavaScript) {
                    score += analyzeJavaScript(((PDActionJavaScript) openAction).getAction());
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading open action JavaScript: " + e.getMessage());
        }

        try {
            PDDocumentCatalog catalog = document.getDocumentCatalog();
            if (catalog.getNames() != null &&
                    catalog.getNames().getJavaScript() != null &&
                    catalog.getNames().getJavaScript().getNames() != null) {

                for (PDActionJavaScript jsAction : catalog.getNames().getJavaScript().getNames().values()) {
                    if (jsAction != null && jsAction.getAction() != null) {
                        score += analyzeJavaScript(jsAction.getAction());
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error reading named JavaScript: " + e.getMessage());
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
                return 4;
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
            if (text.matches(".*://\\S*\\.exe")) {
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

    private int formFieldScore(PDDocument document) {
        try {
            PDAcroForm form = document.getDocumentCatalog().getAcroForm();
            if (form != null && !form.getFields().isEmpty()) {
                return 2;
            }
        } catch (Exception e) {
            System.err.println("Error checking form fields: " + e.getMessage());
        }
        return 0;
    }

    private int metadataScore(PDDocument document) {
        try {
            PDDocumentInformation info = document.getDocumentInformation();
            PDMetadata metadata = document.getDocumentCatalog().getMetadata();
            if ((info != null && info.getCOSObject().size() > 0) || metadata != null) {
                return 1;
            }
        } catch (Exception e) {
            System.err.println("Error checking metadata: " + e.getMessage());
        }
        return 0;
    }

    private int launchActionScore(PDDocument document) {
        try {
            COSBase openActionBase = document.getDocumentCatalog().getCOSObject().getDictionaryObject(COSName.OPEN_ACTION);
            if (openActionBase instanceof COSDictionary) {
                PDAction openAction = PDActionFactory.createAction((COSDictionary) openActionBase);
                if (openAction instanceof PDActionLaunch) {
                    return 3;
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking launch action: " + e.getMessage());
        }
        return 0;
    }

    private int bookmarkActionScore(PDDocument document) {
        try {
            PDDocumentOutline outline = document.getDocumentCatalog().getDocumentOutline();
            if (outline != null) {
                PDOutlineItem current = outline.getFirstChild();
                while (current != null) {
                    PDAction action = current.getAction();
                    if (action instanceof PDActionJavaScript || action instanceof PDActionLaunch) {
                        return 2;
                    }
                    current = current.getNextSibling();
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking bookmark actions: " + e.getMessage());
        }
        return 0;
    }


    private int annotationScore(PDDocument document) {
        int score = 0;
        try {
            for (PDPage page : document.getPages()) {
                List<PDAnnotation> annotations = page.getAnnotations();
                for (PDAnnotation ann : annotations) {
                    String annStr = ann.getCOSObject().toString().toLowerCase();
                    if (annStr.contains("/uri") || annStr.contains("javascript")) {
                        score += 2;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("Error checking annotations: " + e.getMessage());
        }
        return score;
    }
}
