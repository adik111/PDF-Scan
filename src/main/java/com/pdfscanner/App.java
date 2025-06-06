package com.pdfscanner;

import io.javalin.Javalin;
import io.javalin.http.UploadedFile;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.util.Map;

public class App {
    public static void main(String[] args) {
        Javalin app = Javalin.create().start(7000);

        // Sign-up Endpoint
        app.post("/signup", ctx -> {
            String username = ctx.formParam("username");
            String password = ctx.formParam("password");
            boolean created = Database.insertUser(username, password);
            ctx.result(created ? "User created" : "User already exists or error");
        });

        // Login Endpoint
        app.post("/login", ctx -> {
            String username = ctx.formParam("username");
            String password = ctx.formParam("password");
            int userId = Database.authenticateUser(username, password);
            if (userId > 0) {
                Algorithm algorithm = Algorithm.HMAC256("pdfmalwaredtection"); // store securely
                String token = JWT.create()
                        .withClaim("userId", userId)
                        .sign(algorithm);

                ctx.json(Map.of(
                        "success", true,
                        "userId", userId,
                        "token", token,
                        "message", "Login successful."
                ));
            } else {
                ctx.json(Map.of(
                        "success", false,
                        "message", "Invalid credentials"
                ));
            }
        });

        // Upload Endpoint
        app.post("/upload", ctx -> {
            String userIdParam = ctx.formParam("userId");
            if (userIdParam == null) {
                ctx.status(400).result("Missing userId");
                return;
            }

            int userId = Integer.parseInt(userIdParam);
            UploadedFile file = ctx.uploadedFile("file");

            if (file == null || !file.filename().endsWith(".pdf")) {
                ctx.status(400).result("Invalid or missing PDF file");
                return;
            }

            // Save to temp file
            File temp = File.createTempFile("upload-", ".pdf");
            try (InputStream input = file.content()) {
                Files.copy(input, temp.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }

            ScanResult result;
            try {
                PDFScanner scanner = new PDFScanner();
                 result = scanner.scan(temp);
                boolean malicious = result.malicious;
                String classification = result.classification;
                double score = result.score;
                Database.insertScanResult(file.filename(), malicious, classification, score, userId);
// Save result to DB with extended info

            } catch (IOException e) {
                e.printStackTrace();
                ctx.status(500).result("Error scanning file");
                return;
            }

            // Respond with full scan result including classification and score
            ctx.json(result);
        });
    }
}
