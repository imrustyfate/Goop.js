const express = require("express");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const { IpFilter, IpDeniedError } = require("express-ipfilter");
const crypto = require("crypto");
const app = express();
const PORT = 3000;

// Function to generate a hash of the current timestamp
function generateTimestampHash() {
	const timestamp = Date.now().toString();
	return crypto.createHash("sha256").update(timestamp).digest("hex");
}

let currentHash = generateTimestampHash();

// Middleware to log all requests
app.use(morgan("combined"));

// Rate limiting middleware
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10000, // limit each IP to 100 requests per windowMs
	message: "Too many requests from this IP, please try again after 15 minutes",
});
app.use(limiter);

// List of allowed IPs
const allowedIps = ["::1", "127.0.0.1", "::ffff:172.31.196.50"]; // Add allowed IPs here

// IP filter middleware
app.use(IpFilter(allowedIps, { mode: "allow", log: false }));

// Middleware to check referrer and update the hash
app.use((req, res, next) => {
	const referrer = req.get("referrer");
	if (referrer && referrer.includes("*.linkvertise.com")) {
		currentHash = generateTimestampHash();
	}
	next();
});

// Route to serve the current hash in JSON format
app.get('/api/getkey', (req, res) => {
    res.json({ key: currentHash });
});

// Route to authenticate the hash
app.post("/api/authenticate", (req, res) => {
	let hash = req.query.hash;
	if (hash === currentHash) {
		res.send("Authentication successful");
	} else {
		res.send("Authentication failed");
	}
});

// Root route
app.get("/", (req, res) => {
	res.send("Hello, this is your Express server!");
});

// Error handler for IP denied errors
app.use((err, req, res, next) => {
	if (err instanceof IpDeniedError) {
		res.status(403).send("Forbidden");
	} else {
		next(err);
	}
});

app.listen(PORT, () => {
	console.log(`Server is running on http://localhost:${PORT}`);
});
