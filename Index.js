const express = require("express");
const session = require("express-session");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { IpFilter } = require("express-ipfilter");
const crypto = require("crypto");
const os = require("os");

const app = express();
const PORT = 3000;
const ONE_DAY_IN_MS = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
let KEY;
let DURA;
let KEYEXPIRATION;
let KEYGEN = {};
let checkpoint = 0;
const DEBUG_MODE = true;
const BLACKLIST = ["bypass.city"];

// Middleware to log all requests
app.use(morgan("combined"));

// Rate limiting middleware
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP, please try again after 15 minutes",
});
app.use(limiter);

// Session middleware
app.use(
  session({
    secret: "your-secret-key", // Replace with a strong secret key
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === "production",
      maxAge: ONE_DAY_IN_MS, // Session max age in milliseconds
      httpOnly: true, // Ensures the cookie is only accessible via HTTP(S)
      sameSite: true, // Ensures the cookie is only sent with same-site requests
      trustProxy: true,
    },
  })
);

// List of allowed IPs
const allowedIps = [""]; // Add allowed IPs here

// IP filter middleware
app.use(IpFilter(allowedIps, { mode: "deny", log: true }));

app.set("trust proxy", 1);

// Function to generate a hash of the current timestamp
function generateTimestampHash() {
  const timestamp = Date.now().toString();
  return crypto.createHash("sha256").update(timestamp).digest("hex");
}

// Middleware to ensure key existence and validity
app.use((req, res, next) => {
  const now = Date.now();

  if (!req.session.key || now > req.session.dura) {
    req.session.key = generateTimestampHash();
    req.session.dura = now + ONE_DAY_IN_MS;
    req.session.keyGen = true; // Flag to indicate key generation for this session
  }

  // Calculate key expiration time
  KEYEXPIRATION = req.session.dura;

  next();
});

// Middleware to prevent key regeneration on page refresh
app.use((req, res, next) => {
  if (req.session.keyGen) {
    // If key is generated in this session, prevent further generation
    req.session.keyGen = false;
  } else {
    // If key is not generated in this session, send error or handle accordingly
    res.status(403).send("Unauthorized"); // Example: Send 403 Forbidden
    return;
  }
  next();
});

// Route to get the key
app.get("/api/getkey", (req, res) => {
  const referer = req.get("Referer");
  const ipAddress = req.ip;

  // Check if the referer is blacklisted or if key generation is flagged
  if (!referer || BLACKLIST.includes(referer) || !req.session.keyGen) {
    res.status(403).send("Unauthorized");
    return;
  }

  // Send the key if it exists in session
  res.send(req.session.key);
});

// Route to authenticate the hash
app.get("/api/authenticate", (req, res) => {
  const hash = req.query.hash;

  if (!hash || hash !== req.session.key || Date.now() > KEYEXPIRATION) {
    res.status(403).send("Authentication failed");
    return;
  }

  res.send("Authentication successful");
});

// Route to display local IP address
app.get("/ip", (req, res) => {
  const ipAddress = req.ip;
  res.send(`Your IP Address: ${ipAddress}`);
});

// Root route
app.get("/", (req, res) => {
  res.send("Hello, this is your Express server!");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
