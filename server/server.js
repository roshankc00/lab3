const express = require("express");
const bodyParser = require("body-parser");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = "secret_key";

function generateToken(payload) {
  return jwt.sign(payload, SECRET_KEY, { expiresIn: "5d" });
}

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "m@ya000",
  database: "clzusers",
});

db.connect((err) => {
  if (err) {
    console.error("Database connection failed:", err);
    return;
  }
  console.log("Connected to the database.");
});

// Create User
app.post("/users", async (req, res) => {
  const { name, email, password, dob } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const query =
      "INSERT INTO users (name, email, password, dob) VALUES (?, ?, ?, ?)";
    db.query(query, [name, email, hashed, dob], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error creating user.");
      }
      return res
        .status(201)
        .send({ success: true, message: "Signup successfully" });
    });
  } catch (error) {
    console.error("Error during user creation:", error);
    res.status(500).send("Internal server error.");
  }
});

// Seed Admin User
app.post("/seed/admin", async (req, res) => {
  const { name, email, password, dob } = req.body;
  const role = "admin"; // Explicitly set role to 'admin'

  try {
    const hashed = await bcrypt.hash(password, 10);
    const query =
      "INSERT INTO users (name, email, password, dob, role) VALUES (?, ?, ?, ?, ?)";

    db.query(query, [name, email, hashed, dob, role], (err, result) => {
      if (err) {
        console.error("Error creating admin user:", err);
        return res.status(500).send("Error creating admin user.");
      }
      return res
        .status(201)
        .send({ success: true, message: "Admin user created successfully." });
    });
  } catch (error) {
    console.error("Error during user creation:", error);
    res.status(500).send("Internal server error.");
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const query = "SELECT * FROM users WHERE email = ?";
  db.query(query, [email], async (err, results) => {
    if (err) {
      res.status(401).send("Error retrieving user.");
      return;
    }
    if (results.length === 0) {
      res.status(401).send({ success: false, message: "Unauthorized" });
      return;
    }
    console.log(results);
    let isPasswordCorrect = await bcrypt.compare(password, results[0].password);
    if (!isPasswordCorrect) {
      res.status(401).send({ success: false, message: "Unauthorized" });
      return;
    }
    res.status(200).send({
      success: true,
      user: results[0],
      token: generateToken({
        id: results[0].id,
        email: results[0].email,
      }),
    });
  });
});
// Read All Users
app.get("/users", (req, res) => {
  const query = "SELECT * FROM users";
  db.query(query, (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error retrieving users.");
      return;
    }
    res.send(results);
  });
});

// Read User by ID
app.get("/users/:id", (req, res) => {
  const { id } = req.params;
  const query = "SELECT * FROM users WHERE id = ?";
  db.query(query, [id], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error retrieving user.");
      return;
    }
    if (results.length === 0) {
      res.status(404).send("User not found.");
      return;
    }
    res.send(results[0]);
  });
});

app.get("/me", (req, res) => {
  // Extract the Bearer token from the Authorization header
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).send("Authorization token is required.");
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send("Invalid or expired token.");
    }

    console.log(decoded);

    const userId = decoded.id;

    console.log(userId);

    const query = "SELECT * FROM users WHERE id = ?";
    db.query(query, [userId], (err, results) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error retrieving user.");
      }
      if (results.length === 0) {
        return res.status(404).send("User not found.");
      }
      res.send(results[0]); // Return the user data
    });
  });
});

// Update User
app.put("/update", (req, res) => {
  const token =
    req.headers.authorization && req.headers.authorization.split(" ")[1];

  if (!token) {
    return res.status(401).send("Authorization token is required.");
  }

  // Extract the name from the request body
  const { name } = req.body;

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send("Invalid or expired token.");
    }

    const userId = decoded.id;

    // Update only the 'name' field in the users table
    const query = "UPDATE users SET name = ? WHERE id = ?";
    db.query(query, [name, userId], (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).send("Error updating user.");
      }
      if (result.affectedRows === 0) {
        return res.status(404).send("User not found.");
      }
      res.send("User name updated successfully.");
    });
  });
});

// Delete User
app.delete("/users/:id", (req, res) => {
  const { id } = req.params;
  const query = "DELETE FROM users WHERE id = ?";
  db.query(query, [id], (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error deleting user.");
      return;
    }
    if (result.affectedRows === 0) {
      res.status(404).send("User not found.");
      return;
    }
    res.send("User deleted successfully.");
  });
});

// Start the Server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
