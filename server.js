const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const bodyParser = require("body-parser");

async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "restapi",
  });
}

const secretKey = "Hemlig-nyckel";

function verifieraToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Unauthorized: Token is required" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(401).json({ error: "Unauthorized: Invalid token" });
    }
    req.user = decoded;
    next();
  });
}

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const hashPassword = async (password) => {
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  console.log("Generated hashed password:", hashedPassword);
  return hashedPassword;
};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "formulär.html"));
});

app.get("/users", verifieraToken, async (req, res) => {
  try {
    const connection = await getDBConnection();
    const [rows] = await connection.execute("SELECT * FROM users");
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error("SQL Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.get("/users/:id", verifieraToken, async (req, res) => {
  try {
    const connection = await getDBConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [req.params.id]
    );
    await connection.end();

    if (rows.length === 0) {
      res.status(404).json({ error: "User not found" });
    } else {
      res.json(rows[0]);
    }
  } catch (error) {
    console.error("SQL Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.post("/users", async (req, res) => {
  try {
    const connection = await getDBConnection();
    const hashedPassword = await hashPassword(req.body.password); // Hash password
    const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
    const [result] = await connection.execute(sql, [
      req.body.username,
      hashedPassword,
    ]);
    await connection.end();
    res.status(201).json({
      id: result.insertId,
      username: req.body.username,
      message: "Användare skapad",
    });
  } catch (error) {
    console.error("SQL Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

app.put("/users/:id", async (req, res) => {
  try {
    const connection = await getDBConnection();
    const sql = "UPDATE users SET username = ? WHERE id = ?";
    await connection.execute(sql, [req.body.username, req.params.id]);
    await connection.end(); // Release the connection
    res.status(200).json({ message: "User updated successfully" });
  } catch (error) {
    console.error("SQL Error:", error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Login endpoint

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res
        .status(400)
        .json({ error: "Username and password are required" });
    }

    const connection = await getDBConnection();

    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE username = ?",
      [username]
    );

    await connection.end(); // Close the database connection

    if (rows.length === 0) {
      return res.status(404).json({ error: "User not found" });
    }

    const user = rows[0];

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(401).json({ error: "Incorrect password" });
    }

    // Generate JWT token if password is correct
    const token = jwt.sign({ id: user.id }, secretKey, {
      expiresIn: "1h", // Token expires in 1 hour
    });

    // Return JWT token with expiration message
    res.json({ token, message: "Token expires in 1 hour" });
  } catch (error) {
    console.error("Login Error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
