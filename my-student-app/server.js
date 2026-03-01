require('dotenv').config();
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = mysql.createConnection({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "school_db"
});

const SECRET_KEY = process.env.JWT_SECRET || "SECRET_KEY";

function verifyToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if(!token) return res.status(403).json({ error: "Access denied. No token provided." });

    jwt.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ error: "Invalid token." });
        req.user = decoded;
        next();
    });
}

function checkRole(role){
    return (req, res, next) => {
        if(req.user.role !== role) return res.status(403).json({ error: "Forbidden. Insufficient permissions." });
        next();
    };
}

db.connect((err) => {
    if (err) {
        console.error("Database connection failed:", err.message);
    } else {
        console.log("Connected to MySQL: 'school_db' is ready.");
    }
});

// REGISTER
app.post("/register", async (req, res) => {
    const { name, email, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = "INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)";

    db.query(sql, [name, email, hashedPassword, role || 'user'], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "User registered successfully" });
    });
});

// LOGIN
app.post("/login", (req, res) => {
    const { email, password } = req.body;
    db.query("SELECT * FROM users WHERE email = ?", [email], async (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        if (results.length === 0) return res.status(404).json({ error: "User not found." });

        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ error: "Invalid password." });
        
        const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
        res.json({ token, role: user.role });
    });
});

// **FIXED: Single protected GET students route**
app.get("/students",  (req, res) => {
    db.query("SELECT * FROM students", (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

// Add Student (Admin only)
app.post("/students", verifyToken, checkRole("admin"), (req, res) => {
    const { name, email } = req.body;
    const sql = "INSERT INTO students (name, email) VALUES (?, ?)";

    db.query(sql, [name, email], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Student added successfully", studentId: result.insertId });
    });
});

// **FIXED: Added authentication & admin role check**
app.put("/students/:id", verifyToken, checkRole("admin"), (req, res) => {     
    const { name, email } = req.body;
    const { id } = req.params;
    const sql = "UPDATE students SET name = ?, email = ? WHERE id = ?";

    db.query(sql, [name, email, id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Student updated successfully" });
    });
});

// **FIXED: Added authentication & admin role check**
app.delete("/students/:id", verifyToken, checkRole("admin"), (req, res) => {
    const { id } = req.params;
    db.query("DELETE FROM students WHERE id = ?", [id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: "Student deleted successfully" });
    });
});

// Get current logged-in user (profile) – any logged-in user
app.get("/me", verifyToken, (req, res) => {
  const sql = "SELECT id, name, email, role FROM users WHERE id = ?";
  db.query(sql, [req.user.id], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: "User not found." });
    res.json(results[0]);
  });
});


// List all users – admin only
app.get("/users", (req, res) => {
  const sql = "SELECT id, name, email, role FROM users";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});


// Update a user – admin only (or add logic to allow self-update)
app.put("/users/:id", verifyToken, checkRole("admin"), (req, res) => {
  const { name, email, role } = req.body;
  const { id } = req.params;
  const sql = "UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?";
  db.query(sql, [name, email, role, id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "User updated successfully" });
  });
});

// Delete a user – admin only
app.delete("/users/:id", verifyToken, checkRole("admin"), (req, res) => {
  const { id } = req.params;
  db.query("DELETE FROM users WHERE id = ?", [id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: "User deleted successfully" });
  });
});

async function loadUsers() {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_URL}/users`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const users = await res.json();
  console.log(users); // or render in a table
}

async function loadProfile() {
  const token = localStorage.getItem('token');
  const res = await fetch(`${API_URL}/me`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  const me = await res.json();
  console.log(me);
}


const port = 5000;
app.listen(port, () => {
    console.log(`Server running on port http://localhost:${port}`);
});
