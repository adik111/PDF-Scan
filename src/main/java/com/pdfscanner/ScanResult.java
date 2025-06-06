package com.pdfscanner;

public class ScanResult {
    public String filename;
    public boolean malicious;
    public String classification;
    public double score;

    public ScanResult(String filename, boolean malicious, String classification, double score) {
        this.filename = filename;
        this.malicious = malicious;
        this.classification = classification;
        this.score = score;
    }
}
