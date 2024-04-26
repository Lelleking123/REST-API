// Importera nödvändiga
const express = require("express");
const app = express();
const mysql = require("mysql2/promise");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const bodyParser = require("body-parser");

// Funktion för att skapa en anslutning till databasen
async function getDBConnection() {
  return await mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "restapi",
  });
}

// Hemlig nyckel för att signera JWT-token
const secretKey = "Hemlig-nyckel";

// Middleware-funktion för att verifiera JWT-token
function verifieraToken(req, res, next) {
  const token = req.headers["authorization"];

  if (!token) {
    return res.status(401).json({ error: "Obehörig: Token krävs" });
  }

  const tokenParts = token.split(" ");
  if (tokenParts.length !== 2 || tokenParts[0] !== "Bearer") {
    return res.status(401).json({ error: "Obehörig: Ogiltigt tokenformat" });
  }

  const authToken = tokenParts[1];

  jwt.verify(authToken, secretKey, (err, decoded) => {
    if (err) {
      console.error("Token Verification Error:", err);
      return res.status(401).json({ error: "Obehörig: Ogiltigt token" });
    }
    req.user = decoded;
    next();
  });
}

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Funktion för att hasha lösenord med bcrypt
const hashPassword = async (password) => {
  const saltRounds = 10;

  const hashedPassword = await bcrypt.hash(password, saltRounds);
  console.log("Genererad hashat lösenord:", hashedPassword);
  return hashedPassword;
};

// Sänd indexsidan när någon ansluter till rotvägen
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "formulär.html"));
});

// Hämta alla användare från databasen
app.get("/users", async (req, res) => {
  try {
    const connection = await getDBConnection();
    const [rows] = await connection.execute("SELECT * FROM users");
    await connection.end();
    res.json(rows);
  } catch (error) {
    console.error("SQL-fel:", error);
    res.status(500).json({ error: "Internt serverfel" });
  }
});

// Hämta en specifik användare baserat på ID
app.get("/users/:id", async (req, res) => {
  try {
    const connection = await getDBConnection();
    const [rows] = await connection.execute(
      "SELECT * FROM users WHERE id = ?",
      [req.params.id]
    );
    await connection.end();

    if (rows.length === 0) {
      res.status(404).json({ error: "Användare hittades inte" });
    } else {
      res.json(rows[0]);
    }
  } catch (error) {
    console.error("SQL-fel:", error);
    res.status(500).json({ error: "Internt serverfel" });
  }
});

// Skapa en ny användare
app.post("/users", async (req, res) => {
  try {
    const connection = await getDBConnection();
    const hashedPassword = await hashPassword(req.body.password); // Kryptera lösenord
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
    console.error("SQL-fel:", error);
    res.status(500).json({ error: "Internt serverfel" });
  }
});

// Uppdatera en användare
app.put("/users/:id", verifieraToken, async (req, res) => {
  try {
    const connection = await getDBConnection();
    const sql = "UPDATE users SET username = ? WHERE id = ?";
    await connection.execute(sql, [req.body.username, req.params.id]);
    await connection.end(); // Släpp anslutningen
    res.status(200).json({ message: "Användaren uppdaterad" });
  } catch (error) {
    console.error("SQL-fel:", error);
    res.status(500).json({ error: "Internt serverfel" });
  }
});

// Inloggningsendpunkt
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: "Användarnamn och lösenord krävs" });
    }

    const connection = await getDBConnection();

    const [rows] = await connection.execute(
      "SELECT id, password FROM users WHERE username = ?",
      [username]
    );

    await connection.end(); // Stäng databasanslutningen

    if (rows.length === 0) {
      return res.status(404).json({ error: "Användare hittades inte" });
    }

    const user = rows[0];

    const isPasswordCorrect = await bcrypt.compare(password, user.password);

    if (!isPasswordCorrect) {
      return res.status(401).json({ error: "Fel lösenord" });
    }

    // Generera JWT-token om lösenordet är korrekt
    const token = jwt.sign({ id: user.id }, secretKey, {
      expiresIn: "1h", // Tokenet löper ut om 1 timme
    });

    // Returnera JWT-token med meddelande om utgång
    res.json({ token, message: "Tokenet löper ut om 1 timme" });
  } catch (error) {
    console.error("Inloggningsfel:", error);
    return res.status(500).json({ error: "Internt serverfel" });
  }
});

// Lyssna på port
const port = 3000;
app.listen(port, () => {
  console.log(`Servern lyssnar på http://localhost:${port}`);
});
