const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const User = require("./models/User");



dotenv.config();

const MONGODB_URI = process.env.MONGODB_URI;

console.log("MongoDB URI exists:", Boolean(MONGODB_URI));
console.log("MongoDB URI starts correctly:",
    MONGODB_URI?.startsWith("mongodb://") ||
    MONGODB_URI?.startsWith("mongodb+srv://")
);

mongoose.connect(MONGODB_URI)
    .then(() => {
        console.log("MongoDB connected successfully!");
    })
    .catch((error) => {
        console.error("MongoDB connection failed:", error.message);
    });

const app = express();

app.use(cors());
app.use(express.json());

app.get("/", (req, res) => {
    res.json({
        message: "Authentication API is running!"
    });
});

app.get("/api/health", (req, res) => {
    res.json({
        status: "OK",
        database: mongoose.connection.readyState === 1
            ? "Connected"
            : "Not connected"
    });
});

app.post("/api/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "Please fill in all fields"
            });
        }

        if (password.length < 8) {
            return res.status(400).json({
                message: "Password must be at least 8 characters"
            });
        }

        const existingUser = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (existingUser) {
            return res.status(409).json({
                message: "Email already registered"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({
            name,
            email: email.toLowerCase().trim(),
            password: hashedPassword
        });

        res.status(201).json({
            message: "Signup successful",
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error("Signup error:", error.message);

        res.status(500).json({
            message: "Signup failed. Please try again."
        });
    }
});

app.post("/api/login", async (req, res) => {
    console.log("LOGIN ROUTE HIT");
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const user = await User.findOne({
            email: email.toLowerCase().trim()
        });

        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({
            message: "Login successful",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.error("Login error:", error.message);

        res.status(500).json({
            message: "Login failed. Please try again."
        });
    }
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({
            message: "Access denied. Please log in."
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({
                message: "Invalid or expired token."
            });
        }

        req.userId = decoded.userId;
        next();
    });
}

app.get("/api/profile", authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select("-password");

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            });
        }

        res.json({
            message: "Profile retrieved successfully",
            user
        });
    } catch (error) {
        res.status(500).json({
            message: "Unable to retrieve profile"
        });
    }
});

app.post("/api/logout", authenticateToken, (req, res) => {
    res.json({
        message: "Logout successful. Please discard your token."
    });
});

app.post("/api/forgot-password", async (req, res) => {
    try {
        const { email } = req.body;

        if (!email || !email.trim()) {
            return res.status(400).json({
                message: "Please enter your email"
            });
        }

        const user = await User.findOne({
            email: email.toLowerCase().trim()
        });

        // Use the same response whether or not the email exists.
        if (!user) {
            return res.json({
                message: "If the account exists, password-reset instructions will be sent."
            });
        }

        // Email delivery and a secure, single-use reset token
        // still need to be implemented.
        res.json({
            message: "Password-reset delivery is not configured yet."
        });
    } catch (error) {
        console.error("Password reset request error:", error.message);

        res.status(500).json({
            message: "Unable to process the request."
        });
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});