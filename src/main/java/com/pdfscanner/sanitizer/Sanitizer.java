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
        modules.add(new PowerShellStringRemovalModule());
        modules.add(new RemoteLinkRemovalModule());
        modules.add(new MetadataSanitizerModule());
        modules.add(new AcroFormSanitizerModule());
    }

    public void sanitize(PDDocument document) {
        for (SanitizationModule module : modules) {
            module.sanitize(document);
        }
    }
}
