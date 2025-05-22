require("dotenv").config();
const express = require("express");
const prisma = require("@prisma/client");
const { PrismaClient } = prisma;
const bcrypt = require("bcryptjs");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
const prismaClient = new PrismaClient();

app.use(cors());
app.use(express.json());

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  const existing = await prismaClient.account.findUnique({ where: { email } });
  if (existing)
    return res.status(400).json({ message: "Email already registered" });

  const hashed = await bcrypt.hash(password, 10);
  const user = await prismaClient.account.create({
    data: { name, email, password: hashed },
  });

  res.json({ message: "Signup successful", user });
});

// Login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await prismaClient.account.findUnique({ where: { email } });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
  res.json({ message: "Login successful", token });
});

// Middleware for auth
const auth = async (req, res, next) => {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "No token" });

  try {
    const decoded = jwt.verify(header.split(" ")[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ message: "Invalid token" });
  }
};

// Add user
app.post("/dashboard/user", auth, async (req, res) => {
  const { name, email, department } = req.body;
  const subUser = await prismaClient.user.create({
    data: {
      name,
      email,
      department,
      accountId: req.user.userId,
    },
  });
  res.json(subUser);
});

// Get all users for logged-in account
app.get("/dashboard/users", auth, async (req, res) => {
  const users = await prismaClient.user.findMany({
    where: { accountId: req.user.userId },
  });
  res.json(users);
});

// Update a sub-user
app.put("/dashboard/user/:id", auth, async (req, res) => {
  const { name, email, department } = req.body;
  const { id } = req.params;

  const updated = await prismaClient.user.updateMany({
    where: { id, accountId: req.user.userId },
    data: { name, email, department },
  });

  res.json({ message: "User updated", updated });
});

// Delete sub-user
app.delete("/dashboard/user/:id", auth, async (req, res) => {
  const { id } = req.params;
  await prismaClient.user.deleteMany({
    where: { id, accountId: req.user.userId },
  });
  res.json({ message: "User deleted" });
});

app.post('/logout', auth, (req, res) => {
  res.json({ message: 'Logout successful. Please remove token from client.' });
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on http://localhost:${process.env.PORT}`),
);
