// Mẫu code an toàn tương đương samples/vulnerable/SqlInjection.java.

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class UserQuery {

    public ResultSet findUser(Connection conn, String username) throws Exception {
        // SAFE: dùng PreparedStatement với tham số hoá, không nối chuỗi trực tiếp
        PreparedStatement stmt = conn.prepareStatement(
            "SELECT * FROM users WHERE username = ?"
        );
        stmt.setString(1, username);
        return stmt.executeQuery();
    }
}
