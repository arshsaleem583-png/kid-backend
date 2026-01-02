require("dotenv").config();

const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const nodemailer = require("nodemailer");

const app = express();

// ✅ CORS
app.use(cors());
app.use(express.json());

// ✅ IMPORTANT: listen on all interfaces for phone access
const PORT = 3000;

// ✅ MySQL config
const dbConfig = {
  host: "127.0.0.1",
  user: "root",
  password: "",        // <-- apna mysql password
  database: "har_app", // <-- db name
};

let pool = null;

async function initDB() {
  try {
    pool = await mysql.createPool({
      ...dbConfig,
      waitForConnections: true,
      connectionLimit: 10,
      queueLimit: 0,
    });

    await pool.query("SELECT 1");
    console.log("✅ MySQL Connected & Ready");
  } catch (err) {
    console.error("❌ MySQL init failed:", err.message);
    pool = null;
  }
}
initDB();

function requireDB(req, res, next) {
  if (!pool) {
    return res
      .status(500)
      .json({ success: false, message: "DB not connected. Check MySQL config." });
  }
  next();
}

// ✅ logger
app.use((req, res, next) => {
  console.log("➡️", req.method, req.url, req.body);
  next();
});

// ✅ Health check
app.get("/api/health", requireDB, async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, db: true, message: "Server + DB OK" });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, message: "DB query failed" });
  }
});

// ===================== REGISTER =====================
app.post("/api/register", requireDB, async (req, res) => {
  try {
    const { email, password } = req.body;

    const emailLower = String(email || "").trim().toLowerCase();
    const pass = String(password || "");

    if (!emailLower || !pass) {
      return res.json({ success: false, message: "Email & password required" });
    }

    if (pass.length < 6) {
      return res.json({ success: false, message: "Password must be at least 6 characters" });
    }

    const [exist] = await pool.query("SELECT id FROM users WHERE email = ?", [emailLower]);
    if (exist.length > 0) {
      return res.json({ success: false, message: "Email already exists" });
    }

    const hash = await bcrypt.hash(pass, 10);

    await pool.query("INSERT INTO users (email, password_hash) VALUES (?, ?)", [
      emailLower,
      hash,
    ]);

    return res.json({ success: true, message: "Account created" });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error (register)" });
  }
});

// ===================== LOGIN =====================
app.post("/api/login", requireDB, async (req, res) => {
  try {
    const { email, password } = req.body;

    const emailLower = String(email || "").trim().toLowerCase();
    const pass = String(password || "");

    if (!emailLower || !pass) {
      return res.json({ success: false, message: "Email & password required" });
    }

    const [rows] = await pool.query(
      "SELECT id, email, password_hash FROM users WHERE email = ?",
      [emailLower]
    );

    if (rows.length === 0) {
      return res.json({ success: false, message: "User not found. Please Sign Up." });
    }

    const user = rows[0];
    const ok = await bcrypt.compare(pass, user.password_hash);

    if (!ok) {
      return res.json({ success: false, message: "Wrong password" });
    }

    return res.json({ success: true, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error("LOGIN ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error (login)" });
  }
});

// ======================================================
// ✅ REAL OTP FORGOT PASSWORD (Email OTP)
// Endpoints:
// POST /api/auth/forgot-password
// POST /api/auth/verify-reset-otp
// POST /api/auth/reset-password
// ======================================================

function generateOtp6() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

function makeTransporter() {
  // Gmail SMTP
  return nodemailer.createTransport({
    host: "smtp.gmail.com",
    port: 465,
    secure: true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS,
    },
  });
}

async function sendOtpEmail(to, otp) {
  const transporter = makeTransporter();

  const html = `
  <div style="font-family:Arial;padding:16px">
    <h2 style="margin:0 0 10px">Password Reset OTP</h2>
    <p style="margin:0 0 8px">Your OTP is:</p>
    <div style="font-size:28px;font-weight:800;letter-spacing:6px;background:#f3f4f6;display:inline-block;padding:10px 14px;border-radius:10px">
      ${otp}
    </div>
    <p style="margin:14px 0 0;color:#6b7280">This code expires in 5 minutes.</p>
  </div>`;

  await transporter.sendMail({
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: "Your Password Reset OTP",
    html,
  });
}

// POST: send otp
app.post("/api/auth/forgot-password", requireDB, async (req, res) => {
  try {
    const emailLower = String(req.body.email || "").trim().toLowerCase();
    if (!emailLower) return res.json({ success: false, message: "Email required" });

    const [rows] = await pool.query("SELECT id, email FROM users WHERE email = ?", [emailLower]);

    // ✅ Security: always return success
    if (rows.length === 0) {
      return res.json({ success: true, message: "If email exists, OTP sent." });
    }

    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
      return res.status(500).json({
        success: false,
        message: "SMTP not configured. Add SMTP_USER & SMTP_PASS in .env",
      });
    }

    const otp = generateOtp6();
    const otpHash = await bcrypt.hash(otp, 10);
    const expires = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    await pool.query(
      "UPDATE users SET reset_otp_hash=?, reset_otp_expires=?, reset_otp_attempts=0 WHERE email=?",
      [otpHash, expires, emailLower]
    );

    await sendOtpEmail(emailLower, otp);

    return res.json({ success: true, message: "OTP sent to your email." });
  } catch (err) {
    console.error("FORGOT PASSWORD ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error (forgot-password)" });
  }
});

// POST: verify otp
app.post("/api/auth/verify-reset-otp", requireDB, async (req, res) => {
  try {
    const emailLower = String(req.body.email || "").trim().toLowerCase();
    const otp = String(req.body.otp || "").trim();

    if (!emailLower || !otp) {
      return res.json({ success: false, message: "Email & OTP required" });
    }

    const [rows] = await pool.query(
      "SELECT id, reset_otp_hash, reset_otp_expires, reset_otp_attempts FROM users WHERE email=?",
      [emailLower]
    );

    if (rows.length === 0) return res.json({ success: false, message: "User not found" });

    const user = rows[0];

    if (!user.reset_otp_hash || !user.reset_otp_expires) {
      return res.json({ success: false, message: "OTP not requested." });
    }

    if (new Date(user.reset_otp_expires).getTime() < Date.now()) {
      return res.json({ success: false, message: "OTP expired. Request again." });
    }

    if ((user.reset_otp_attempts || 0) >= 5) {
      return res.json({ success: false, message: "Too many attempts. Request new OTP." });
    }

    const ok = await bcrypt.compare(otp, user.reset_otp_hash);

    await pool.query(
      "UPDATE users SET reset_otp_attempts = reset_otp_attempts + 1 WHERE email=?",
      [emailLower]
    );

    if (!ok) return res.json({ success: false, message: "Invalid OTP." });

    return res.json({ success: true, message: "OTP verified." });
  } catch (err) {
    console.error("VERIFY OTP ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error (verify-reset-otp)" });
  }
});

// POST: reset password
app.post("/api/auth/reset-password", requireDB, async (req, res) => {
  try {
    const emailLower = String(req.body.email || "").trim().toLowerCase();
    const otp = String(req.body.otp || "").trim();
    const newPassword = String(req.body.newPassword || "");

    if (!emailLower || !otp || !newPassword) {
      return res.json({ success: false, message: "Email, OTP, newPassword required" });
    }

    const [rows] = await pool.query(
      "SELECT id, reset_otp_hash, reset_otp_expires FROM users WHERE email=?",
      [emailLower]
    );

    if (rows.length === 0) return res.json({ success: false, message: "User not found" });

    const user = rows[0];

    if (!user.reset_otp_hash || !user.reset_otp_expires) {
      return res.json({ success: false, message: "OTP not requested." });
    }

    if (new Date(user.reset_otp_expires).getTime() < Date.now()) {
      return res.json({ success: false, message: "OTP expired. Request again." });
    }

    const ok = await bcrypt.compare(otp, user.reset_otp_hash);
    if (!ok) return res.json({ success: false, message: "Invalid OTP." });

    const hash = await bcrypt.hash(newPassword, 10);

    await pool.query(
      "UPDATE users SET password_hash=?, reset_otp_hash=NULL, reset_otp_expires=NULL, reset_otp_attempts=0 WHERE email=?",
      [hash, emailLower]
    );

    return res.json({ success: true, message: "Password updated successfully." });
  } catch (err) {
    console.error("RESET PASSWORD ERROR:", err);
    return res.status(500).json({ success: false, message: "Server error (reset-password)" });
  }
});

// ✅ Global error handler
app.use((err, req, res, next) => {
  console.error("UNHANDLED ERROR:", err);
  res.status(500).json({ success: false, message: "Unhandled server error" });
});

// ✅ IMPORTANT: host 0.0.0.0 so phone can access
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running: http://0.0.0.0:${PORT}`);
});
