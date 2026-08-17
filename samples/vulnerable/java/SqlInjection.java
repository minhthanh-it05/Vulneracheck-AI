// Mẫu code có lỗ hổng SQL Injection (CWE-89) — dùng để test phát hiện.

import java.sql.Connection;
import java.sql.Statement;

public class SqlInjection {

    public void findUser(Connection conn, String username) throws Exception {
        Statement stmt = conn.createStatement();
        // VULNERABLE: user input được nối trực tiếp vào câu SQL
        stmt.executeQuery("SELECT * FROM users WHERE username = '" + username + "'");
    }

    public void runCommand(String userInput) throws Exception {
        // VULNERABLE: command injection qua Runtime.exec
        Runtime.getRuntime().exec("cmd.exe /c " + userInput);
    }
}
