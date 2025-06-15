    package com.pdfscanner;

    import com.auth0.jwt.JWTVerifier;
    import com.auth0.jwt.interfaces.DecodedJWT;
    import io.javalin.Javalin;
    import io.javalin.http.UploadedFile;

    import com.auth0.jwt.JWT;
    import com.auth0.jwt.algorithms.Algorithm;

    import java.io.File;
    import java.io.IOException;
    import java.io.InputStream;
    import java.nio.file.Files;
    import java.util.List;
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

            app.post("/admin/login", ctx -> {
                String username = ctx.formParam("username");
                String password = ctx.formParam("password");
                int adminId = Database.authenticateAdmin(username, password);

                if (adminId > 0) {
                    Algorithm algorithm = Algorithm.HMAC256("pdfmalwaredtection");
                    String token = JWT.create()
                            .withClaim("adminId", adminId)
                            .sign(algorithm);

                    ctx.json(Map.of(
                            "success", true,
                            "adminId", adminId,
                            "token", token,
                            "message", "Admin login successful."
                    ));
                } else {
                    ctx.json(Map.of(
                            "success", false,
                            "message", "Invalid credentials"
                    ));
                }
            });

    //       Database.insertAdmin("admin", "1234");
            app.get("/admin/dashboard", ctx -> {
                String token = ctx.header("Authorization");
                if (token == null || !token.startsWith("Bearer ")) {
                    ctx.status(401).result("Unauthorized");
                    return;
                }

                token = token.replace("Bearer ", "");
                try {
                    Algorithm algorithm = Algorithm.HMAC256("pdfmalwaredtection");
                    JWTVerifier verifier = JWT.require(algorithm).build();
                    DecodedJWT jwt = verifier.verify(token);
                    int adminId = jwt.getClaim("adminId").asInt();

                    // valid admin, return dashboard data
                    List<Map<String, Object>> data = Database.getAllUserScans();
                    ctx.json(data);

                } catch (Exception e) {
                    ctx.status(401).result("Invalid token");
                }
            });

            // Sanitize PDF and return cleaned version
            app.post("/sanitize", ctx -> {
                UploadedFile file = ctx.uploadedFile("file");
                if (file == null || !file.filename().endsWith(".pdf")) {
                    ctx.status(400).result("Invalid or missing PDF file");
                    return;
                }

                File inputTemp = File.createTempFile("input-", ".pdf");
                File outputTemp = File.createTempFile("cleaned-", ".pdf");

                try (InputStream input = file.content()) {
                    Files.copy(input, inputTemp.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                }

                PDFScanner scanner = new PDFScanner();
                ScanResult result = scanner.scan(inputTemp);

                if (!result.malicious) {
                    ctx.result("PDF is already clean or just suspicious. No need to sanitize.");
                    return;
                }

                boolean cleaned = PDFSanitizer.cleanPDF(inputTemp, outputTemp);
                if (!cleaned) {
                    ctx.status(500).result("Failed to clean PDF");
                    return;
                }

                // Return sanitized file
                ctx.contentType("application/pdf");
                ctx.header("Content-Disposition", "attachment; filename=\"cleaned_" + file.filename() + "\"");
                ctx.result(Files.readAllBytes(outputTemp.toPath()));
            });





        }
    }
