package com.pdfscanner;
import org.mindrot.jbcrypt.BCrypt;

import java.sql.*;

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

    public static void insertScanResult(String filename, boolean malicious, int userId) {
        try (Connection conn = connect()) {
            PreparedStatement stmt = conn.prepareStatement("INSERT INTO scans(user_id, filename, malicious) VALUES (?, ?, ?)");
            stmt.setInt(1, userId);
            stmt.setString(2, filename);
            stmt.setBoolean(3, malicious);
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
