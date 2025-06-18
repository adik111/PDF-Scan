package com.pdfscanner.sanitizer;

import org.apache.pdfbox.pdmodel.PDDocument;

import java.util.ArrayList;
import java.util.List;

public class Sanitizer {

    private final List<SanitizationModule> modules;

    public Sanitizer() {
        modules = new ArrayList<>();
        modules.add(new JavaScriptRemovalModule());
        modules.add(new LaunchActionRemovalModule());
        modules.add(new EmbeddedFileRemovalModule());
    }

    public void sanitize(PDDocument document) {
        for (SanitizationModule module : modules) {
            module.sanitize(document);
        }
    }
}
