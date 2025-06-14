require("dotenv").config();
const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  const existing = await prisma.account.findUnique({ where: { email } });
  if (existing) {
    return res.status(400).json({ message: "Email already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await prisma.account.create({
    data: { name, email, password: hashedPassword },
  });

  res.json({ message: "Signup successful", user });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await prisma.account.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  res.json({ message: "Login successful", token });
});

// Auth middleware
const auth = (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token provided" });

  try {
    const token = header.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// Add sub-user
app.post("/dashboard/user", auth, async (req, res) => {
  const { name, email, department } = req.body;

  const subUser = await prisma.user.create({
    data: {
      name,
      email,
      department,
      accountId: req.user.userId,
    },
  });

  res.json(subUser);
});

// Get all sub-users
app.get("/dashboard/users", auth, async (req, res) => {
  const users = await prisma.user.findMany({
    where: { accountId: req.user.userId },
  });
  res.json(users);
});

// Update sub-user by ID (FIXED)
app.put("/dashboard/user/:id", auth, async (req, res) => {
  const { name, email, department } = req.body;
  const { id } = req.params;

  try {
    const existing = await prisma.user.findFirst({
      where: { id, accountId: req.user.userId },
    });

    if (!existing) {
      return res.status(404).json({ message: "Sub-user not found" });
    }

    const updatedUser = await prisma.user.update({
      where: { id },
      data: { name, email, department },
    });

    res.json({ message: "User updated", updatedUser });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ message: "Update failed", error: error.message });
  }
});

// Delete sub-user
app.delete("/dashboard/user/:id", auth, async (req, res) => {
  const { id } = req.params;

  try {
    const deleted = await prisma.user.deleteMany({
      where: { id, accountId: req.user.userId },
    });

    if (deleted.count === 0) {
      return res
        .status(404)
        .json({ message: "User not found or not authorized" });
    }

    res.json({ message: "User deleted" });
  } catch (error) {
    console.error("Delete error:", error);
    res.status(500).json({ message: "Delete failed", error: error.message });
  }
});

// Home - API overview
app.get("/", (req, res) => {
  const baseUrl = "https://crud-api-5f45.onrender.com";
  res.send(`
    <h1>CRUD API - Endpoints</h1>
    <ul>
      <li>POST ${baseUrl}/signup</li>
      <li>POST ${baseUrl}/login</li>
      <li>POST ${baseUrl}/dashboard/user</li>
      <li>GET ${baseUrl}/dashboard/users</li>
      <li>PUT ${baseUrl}/dashboard/user/:id</li>
      <li>DELETE ${baseUrl}/dashboard/user/:id</li>
    </ul>
    <p><strong>Note:</strong> All /dashboard routes require Bearer token in Authorization header.</p>
  `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log(`Server running at http://localhost:${PORT}`),
);
