const express = require("express");
const session = require("express-session");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { IpFilter } = require("express-ipfilter");
const crypto = require("crypto");
const os = require("os");

const app = express();
const PORT = 3000;
const ONE_DAY_IN_MS = 9000; // 24 hours in milliseconds
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
      maxAge: ONE_DAY_IN_MS, // Adjust maxAge as needed
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

// Function to get the local IP address
const getLocalIpAddress = () => {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const net of interfaces[name]) {
      // Skip over non-ipv4 and internal (i.e., 127.0.0.1) addresses
      if (net.family === "IPv4" && !net.internal) {
        return net.address;
      }
    }
  }
  return null;
};

// Middleware to ensure key existence and validity
app.use((req, res, next) => {
  const now = Date.now();
  const keyExpiration = req.session.keyExpiration || 0;

  if (!req.session.key || now > keyExpiration) {
    req.session.key = generateTimestampHash();
    req.session.keyExpiration = now + ONE_DAY_IN_MS; // Key TTL of 24 hours
  }
  next();
});

let checkpoint = 0;
let KEY = 0;

app.get("/api/getkey", (req, res) => {
  const referer = req.get("Referer");
  console.log(referer);
  const ipAddress = getLocalIpAddress();
  console.log(`Local IP Address: ${ipAddress}`);
  // Check if the referer is blacklisted
  if (!referer || referer && !referer.includes("linkvertise.com") || referer && referer.includes("bypass.city")) {
    res.send("phuck u");
    return;
  }

  // Check if the checkpoint is set
  if (checkpoint !== 0) {
    res.send("phuck u");
    return;
  }

  checkpoint = 1;

  // If in debug mode, reset the checkpoint
  if (DEBUG_MODE) {
    checkpoint = 0;
  }

  // Get the key from the session
  KEY = req.session.key;

  // Send the key if it exists, otherwise send an error message
  if (KEY) {
    res.send(KEY);
  } else {
    res.send("phuck u");
  }
});

app.get("/api/getkeyy", (req, res) => {
  const referer = req.get("Referer");
  console.log(referer);
  const ipAddress = getLocalIpAddress();
  console.log(`Local IP Address: ${ipAddress}`);
  // Check if the referer is blacklisted
  if (!referer || referer && !referer.includes("linkvertise.com") || referer && referer.includes("bypass.city")) {
    res.send("phuck u");
    return;
  }

  // Check if the checkpoint is set
  if (checkpoint !== 0) {
    res.send("phuck u");
    return;
  }

  checkpoint = 1;

  // If in debug mode, reset the checkpoint
  if (DEBUG_MODE) {
    checkpoint = 0;
  }

  // Get the key from the session
  KEY = req.session.key;

  // Send the key if it exists, otherwise send an error message
  if (KEY) {
    res.send(KEY);
  } else {
    res.send("phuck u");
  }
});

// Route to authenticate the hash
app.get("/api/authenticate", (req, res) => {
  const ipAddress = getLocalIpAddress();
  console.log(`Local IP Address: ${ipAddress}`);
  const hash = req.query.hash;
  if (hash == KEY && Date.now() < req.session.keyExpiration) {
    res.send("Authentication successful");
    // Optionally, reset the key after successful authentication
    req.session.key = generateTimestampHash();
    req.session.keyExpiration = Date.now() + 1;
  } else {
    res.send("Authentication failed");
  }
});

app.get("/ip", (req, res) => res.send(req.ip));

// Root route
app.get("/", (req, res) => {
  res.send("Hello, this is your Express server!");
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
