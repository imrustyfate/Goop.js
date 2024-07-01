const express = require("express");
const session = require("express-session");
const crypto = require("crypto");

const app = express();
const PORT = 3000;
const KEY_DURATION = 25 * 1000; // 25 seconds in milliseconds

// Middleware to log all requests
app.use((req, res, next) => {
  console.log(`Incoming request: ${req.method} ${req.url}`);
  next();
});

// Session middleware
app.use(
  session({
    secret: "your-secret-key", // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: KEY_DURATION, // Session max age in milliseconds
    },
  })
);

// Function to generate a random key
function generateRandomKey() {
  return crypto.randomBytes(20).toString('hex');
}

// Middleware to generate and store a key in session
app.use((req, res, next) => {
  if (!req.session.key || Date.now() > req.session.expiresAt) {
    req.session.key = generateRandomKey();
    req.session.expiresAt = Date.now() + KEY_DURATION;
  }
  next();
});

// Route to get the key
app.get("/api/getkey", (req, res) => {
  if (!req.session.key || Date.now() > req.session.expiresAt) {
    res.status(403).send("Key expired or not generated");
    return;
  }
  res.send(req.session.key);
});

// Route to authenticate the key
app.get("/api/authenticate", (req, res) => {
  const { key } = req.query.wl;
  if (!key || key !== req.session.key || Date.now() > req.session.expiresAt) {
    res.send("Authentication failed");
    return;
  }
  res.send("Authentication successful");
});

// Root route
app.get("/", (req, res) => {
  res.send("Hello, this is your Express server!");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
