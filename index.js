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

app.put("/dashboard/user/:id", auth, async (req, res) => {
  const { name, email, department } = req.body;
  const id = parseInt(req.params.id, 10); // Convert to number if your ID is Int

  try {
    const subUser = await prismaClient.user.findFirst({
      where: {
        id,
        accountId: req.user.userId,
      },
    });

    if (!subUser) {
      return res.status(404).json({ message: "User not found or unauthorized" });
    }

    const updated = await prismaClient.user.update({
      where: { id },
      data: { name, email, department },
    });

    res.json({ message: "User updated", updated });
  } catch (error) {
    console.error("Update error:", error);
    res.status(500).json({ message: "Something went wrong" });
  }
});


// Delete sub-user
app.delete("/dashboard/user/:id", auth, async (req, res) => {
  const { id } = req.params;
  await prismaClient.user.deleteMany({
    where: { id, accountId: req.user.userId },
  });
  res.json({ message: "User deleted" });
});

app.get("/", (req, res) => {
  const baseUrl = "https://crud-api-5f45.onrender.com";
  res.send(`
    <h1>CRUD API - Available Endpoints</h1>
    <table border="1" cellpadding="10" cellspacing="0" style="border-collapse: collapse; width: 100%; max-width: 800px;">
      <thead style="background-color: #f2f2f2;">
        <tr>
          <th>Method</th>
          <th>Full URL</th>
          <th>Description</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>POST</td>
          <td><code>${baseUrl}/signup</code></td>
          <td>Signup new user (name, email, password)</td>
        </tr>
        <tr>
          <td>POST</td>
          <td><code>${baseUrl}/login</code></td>
          <td>Login user (email, password)</td>
        </tr>
        <tr>
          <td>POST</td>
          <td><code>${baseUrl}/logout</code></td>
          <td>Logout user (client removes token)</td>
        </tr>
        <tr>
          <td>POST</td>
          <td><code>${baseUrl}/dashboard/user</code></td>
          <td>Add sub-user (name, email, department)</td>
        </tr>
        <tr>
          <td>GET</td>
          <td><code>${baseUrl}/dashboard/users</code></td>
          <td>Get all sub-users created by logged-in user</td>
        </tr>
        <tr>
          <td>PUT</td>
          <td><code>${baseUrl}/dashboard/user/:id</code></td>
          <td>Update sub-user by ID</td>
        </tr>
        <tr>
          <td>DELETE</td>
          <td><code>${baseUrl}/dashboard/user/:id</code></td>
          <td>Delete sub-user by ID</td>
        </tr>
      </tbody>
    </table>
    <p><em>Note: All /dashboard routes require an Authorization header with a valid Bearer token.</em></p>
  `);
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on http://localhost:${process.env.PORT}`),
);
