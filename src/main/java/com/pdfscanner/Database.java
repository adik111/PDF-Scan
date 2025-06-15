package com.pdfscanner;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Database {
    static final String DB_URL = "jdbc:mysql://localhost:3306/pdf_scanner";
    static final String USER = "root"; // replace with your MySQL username
    static final String PASS = "root"; // replace with your MySQL password

    public static Connection connect() throws SQLException {
        return DriverManager.getConnection(DB_URL, USER, PASS);
    }

    public static boolean insertUser(String username, String password) {
        try (Connection conn = connect()) {
            String hashed = BCrypt.hashpw(password, BCrypt.gensalt());
            PreparedStatement stmt = conn.prepareStatement("INSERT INTO users(username, password) VALUES (?, ?)");
            stmt.setString(1, username);
            stmt.setString(2, hashed);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // When authenticating, fetch hashed password and compare
    public static int authenticateUser(String username, String password) {
        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement("SELECT id, password FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String hashed = rs.getString("password");
                if (BCrypt.checkpw(password, hashed)) {
                    return rs.getInt("id");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    public static void insertScanResult(String filename, boolean malicious, String classification, double score, int userId) {
        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement(
                    "INSERT INTO scans(user_id, filename, malicious, classification, score) VALUES (?, ?, ?, ?, ?)"
            );
            stmt.setInt(1, userId);
            stmt.setString(2, filename);
            stmt.setBoolean(3, malicious);
            stmt.setString(4, classification);
            stmt.setDouble(5, score);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static List<ScanResult> getScanHistory(int userId) {
        List<ScanResult> history = new ArrayList<>();
        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT filename, malicious, classification, score FROM scans WHERE user_id = ?"
            );
            stmt.setInt(1, userId);
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                String filename = rs.getString("filename");
                boolean malicious = rs.getBoolean("malicious");
                String classification = rs.getString("classification");
                double score = rs.getDouble("score");
                history.add(new ScanResult(filename, malicious, classification, score));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return history;
    }

    public static int authenticateAdmin(String username, String password) {
        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement("SELECT id, password FROM admin WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                String hashed = rs.getString("password");
                if (BCrypt.checkpw(password, hashed)) {
                    return rs.getInt("id");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }
    public static boolean insertAdmin(String username, String password) {
        try (Connection conn = connect()) {
            String hashed = BCrypt.hashpw(password, BCrypt.gensalt());
            PreparedStatement stmt = conn.prepareStatement("INSERT INTO admin(username, password) VALUES (?, ?)");
            stmt.setString(1, username);
            stmt.setString(2, hashed);
            stmt.executeUpdate();
            return true;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    public static List<Map<String, Object>> getAllUserScans() {
        List<Map<String, Object>> result = new ArrayList<>();
        String query = "SELECT u.id AS userId, u.username, s.filename, s.malicious " +
                "FROM users u LEFT JOIN scans s ON u.id = s.user_id ORDER BY u.id";

        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement(query);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                Map<String, Object> record = new HashMap<>();
                record.put("userId", rs.getInt("userId"));
                record.put("username", rs.getString("username"));
                record.put("filename", rs.getString("filename"));
                record.put("malicious", rs.getObject("malicious")); // nullable if no scans
                result.add(record);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return result;
    }






}
