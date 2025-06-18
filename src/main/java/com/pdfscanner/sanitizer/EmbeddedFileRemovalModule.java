package com.pdfscanner.sanitizer;

import java.util.List;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFileAttachment;

public class EmbeddedFileRemovalModule implements SanitizationModule {
    @Override
    public void sanitize(PDDocument document) {
        try {
            for (PDPage page : document.getPages()) {
                List<PDAnnotation> annotations = page.getAnnotations();
                annotations.removeIf(ann -> ann instanceof PDAnnotationFileAttachment);
            }

            COSDictionary catalogDict = document.getDocumentCatalog().getCOSObject();
            if (catalogDict.containsKey(COSName.NAMES)) {
                catalogDict.removeItem(COSName.NAMES);
                System.out.println("Embedded files removed.");
            }

        } catch (Exception e) {
            System.err.println("Error removing embedded files: " + e.getMessage());
        }
    }
}
