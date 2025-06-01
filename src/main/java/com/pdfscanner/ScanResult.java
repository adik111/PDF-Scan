package com.pdfscanner;

public class ScanResult {
    public String filename;
    public boolean malicious;

    public ScanResult(String filename, boolean malicious) {
        this.filename = filename;
        this.malicious = malicious;
    }
}
