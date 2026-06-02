// ═══════════════════════════════════════════════════════════════════
//  AXION — Backend Server  (production-ready)
//  Node.js + Express
//  Handles: checkout submissions, USDT payment tracking, email alerts
//
//  ⚠️  SETUP (5 min):
//  1. cp .env.example .env  →  qemutzoeqvlbiuze
//  2. Replace BYBIT_WALLET in public/checkout.html with your TRC-20 address
//  3. npm install  →  node server.js  (or npm start)
// ═══════════════════════════════════════════════════════════════════

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const nodemailer = require('nodemailer');
const path       = require('path');
const fs         = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── SECURITY MIDDLEWARE ──────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*',
  methods: ['GET', 'POST', 'PATCH'],
}));
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting — 10 checkout attempts per IP per 15 minutes
const checkoutLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many requests. Please try again in 15 minutes.' }
});

const contactLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 3,
  message: { success: false, error: 'Too many messages. Please wait a minute.' }
});

// ── STATIC FILES (Sitting in Root) ───────────────────────────────
// Security shield: Block sensitive backend files from being read by visitors
app.use((req, res, next) => {
  const forbidden = ['/server.js', '/orders.json', '/package.json', '/package-lock.json'];
  if (forbidden.includes(req.path.toLowerCase())) {
    return res.status(403).send('Access Denied');
  }
  next();
});
// Serve your HTML/CSS files directly from the main directory
app.use(express.static(__dirname));

// ── FILE-BASED ORDER STORAGE ─────────────────────────────────────
// For production: swap with Postgres / MongoDB / Supabase
const ORDERS_FILE = path.join(__dirname, 'orders.json');

function loadOrders() {
  try {
    if (!fs.existsSync(ORDERS_FILE)) return [];
    return JSON.parse(fs.readFileSync(ORDERS_FILE, 'utf8'));
  } catch (e) {
    console.error('loadOrders error:', e.message);
    return [];
  }
}

function saveOrder(order) {
  const orders = loadOrders();
  orders.push(order);
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));
  return order;
}

// ── EMAIL SETUP ──────────────────────────────────────────────────
// Uses Gmail App Password.
// Google Account → Security → 2-Step Verification → App passwords
const transporter = process.env.GMAIL_USER
  ? nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS,
      },
    })
  : null;

async function sendAdminAlert(order) {
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: `"AXION Payments" <${process.env.GMAIL_USER}>`,
      to: process.env.ADMIN_EMAIL || process.env.GMAIL_USER,
      subject: `💰 New AXION Order — ${order.plan} (${order.billing}) from ${order.company}`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;background:#060609;color:#F0EDF8;padding:32px;border-radius:12px">
          <h2 style="color:#AAFF45;margin-bottom:24px">New AXION Order</h2>
          <table style="width:100%;border-collapse:collapse">
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Name</td><td style="padding:8px 0;font-weight:600">${order.fname} ${order.lname}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Email</td><td style="padding:8px 0"><a href="mailto:${order.email}" style="color:#AAFF45">${order.email}</a></td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Company</td><td style="padding:8px 0">${order.company}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Plan</td><td style="padding:8px 0;color:#AAFF45;font-weight:600">${order.plan} (${order.billing})</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Team size</td><td style="padding:8px 0">${order.teamsize || 'Not specified'}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Payment</td><td style="padding:8px 0">${order.paymentMethod.toUpperCase()}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">TXID</td><td style="padding:8px 0;font-family:monospace;font-size:12px;word-break:break-all;color:#AAFF45">${order.txid}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Submitted</td><td style="padding:8px 0">${new Date(order.timestamp).toLocaleString()}</td></tr>
            <tr><td style="padding:8px 0;color:#9490A3;font-size:14px">Order ID</td><td style="padding:8px 0;font-family:monospace;font-size:12px">${order.orderId}</td></tr>
          </table>
          <hr style="border-color:rgba(255,255,255,0.1);margin:24px 0">
          <p style="color:#9490A3;font-size:13px">⚡ Action required: Verify the TXID on TronScan, then activate the user's account or reply with credentials.</p>
          <a href="https://tronscan.org/#/transaction/${order.txid}" style="display:inline-block;margin-top:12px;background:#AAFF45;color:#060609;padding:10px 20px;border-radius:8px;text-decoration:none;font-weight:600;font-size:14px">Verify on TronScan →</a>
        </div>
      `,
    });
  } catch (e) {
    console.error('Admin email failed:', e.message);
  }
}

async function sendCustomerConfirmation(order) {
  if (!transporter) return;
  try {
    await transporter.sendMail({
      from: `"AXION" <${process.env.GMAIL_USER}>`,
      to: order.email,
      subject: `Your AXION ${order.plan} trial is being activated 🎉`,
      html: `
        <div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#060609;color:#F0EDF8;padding:40px;border-radius:12px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:32px">
            <div style="width:32px;height:32px;background:#AAFF45;border-radius:6px;display:flex;align-items:center;justify-content:center;font-weight:900;color:#060609;font-size:16px">A</div>
            <span style="font-family:sans-serif;font-weight:800;font-size:1.2rem">AXION</span>
          </div>
          <h1 style="font-size:1.8rem;font-weight:800;letter-spacing:-.03em;margin-bottom:12px">You're in, ${order.fname}! 🚀</h1>
          <p style="color:#9490A3;margin-bottom:24px;line-height:1.7">We've received your payment and we're verifying your USDT transaction now. This typically takes 15–30 minutes.</p>
          <div style="background:#0D0B14;border:1px solid rgba(255,255,255,0.07);border-radius:12px;padding:20px;margin-bottom:24px">
            <div style="font-size:12px;color:#524F60;text-transform:uppercase;letter-spacing:.08em;margin-bottom:12px;font-family:monospace">Order summary</div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px"><span style="color:#9490A3">Plan</span><span style="color:#AAFF45;font-weight:600">${order.plan} (${order.billing})</span></div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px"><span style="color:#9490A3">Company</span><span>${order.company}</span></div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.07);font-size:14px"><span style="color:#9490A3">Trial period</span><span>14 days free</span></div>
            <div style="display:flex;justify-content:space-between;padding:8px 0;font-size:14px"><span style="color:#9490A3">Order ID</span><span style="font-family:monospace;font-size:12px">${order.orderId}</span></div>
          </div>
          <p style="color:#9490A3;font-size:14px;line-height:1.7;margin-bottom:24px">Once verified, you'll receive another email with your login credentials and a direct link to your premium dashboard.</p>
          <p style="color:#9490A3;font-size:14px;line-height:1.7">Questions? Reply to this email or contact <a href="mailto:sultan@axion.ai" style="color:#AAFF45">sultan@axion.ai</a></p>
          <hr style="border-color:rgba(255,255,255,0.07);margin:32px 0">
          <p style="color:#524F60;font-size:12px">AXION · axion.ai</p>
        </div>
      `,
    });
  } catch (e) {
    console.error('Customer email failed:', e.message);
  }
}

// ── ROUTES ───────────────────────────────────────────────────────

// Health check — useful for Render/Railway uptime pings
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Checkout submission
app.post('/api/checkout', checkoutLimiter, async (req, res) => {
  const { fname, lname, email, company, plan, billing, txid, paymentMethod, teamsize, timestamp } = req.body;

  // Required fields
  if (!fname || !lname || !email || !company || !plan || !txid) {
    return res.status(400).json({ success: false, error: 'Missing required fields.' });
  }

  // Email
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ success: false, error: 'Invalid email address.' });
  }

  // TXID basic check
  if (txid.trim().length < 20) {
    return res.status(400).json({ success: false, error: 'Invalid transaction hash.' });
  }

  // Plan
  const validPlans = ['starter', 'growth', 'enterprise'];
  if (!validPlans.includes(plan)) {
    return res.status(400).json({ success: false, error: 'Invalid plan.' });
  }

  // XSS-safe sanitization
  const sanitize = (str) => String(str).replace(/[<>"'&]/g, (c) => ({
    '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#x27;', '&': '&amp;'
  }[c]));

  const orderId = 'AXN-' + Date.now() + '-' + Math.random().toString(36).substr(2, 5).toUpperCase();

  const order = {
    orderId,
    fname:         sanitize(fname.trim()),
    lname:         sanitize(lname.trim()),
    email:         email.trim().toLowerCase(),
    company:       sanitize(company.trim()),
    plan,
    billing:       billing || 'annual',
    txid:          txid.trim(),
    paymentMethod: paymentMethod || 'usdt',
    teamsize:      teamsize || '',
    timestamp:     timestamp || new Date().toISOString(),
    status:        'pending_verification',
    ip:            req.ip,
    createdAt:     new Date().toISOString(),
  };

  try {
    saveOrder(order);
    await sendAdminAlert(order);
    await sendCustomerConfirmation(order);
    res.json({ success: true, orderId });
  } catch (e) {
    console.error('Checkout error:', e);
    res.status(500).json({ success: false, error: 'Server error. Please contact support.' });
  }
});

// Get all orders — admin only
app.get('/api/admin/orders', (req, res) => {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  res.json(loadOrders());
});

// Update order status
app.patch('/api/admin/orders/:orderId', (req, res) => {
  if (req.headers['x-admin-key'] !== process.env.ADMIN_KEY) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const orders = loadOrders();
  const idx = orders.findIndex(o => o.orderId === req.params.orderId);
  if (idx === -1) return res.status(404).json({ error: 'Order not found' });
  orders[idx] = { ...orders[idx], ...req.body, updatedAt: new Date().toISOString() };
  fs.writeFileSync(ORDERS_FILE, JSON.stringify(orders, null, 2));
  res.json({ success: true, order: orders[idx] });
});

// Contact form
app.post('/api/contact', contactLimiter, async (req, res) => {
  const { name, email, message } = req.body;
  if (!name || !email || !message) {
    return res.status(400).json({ success: false, error: 'All fields required.' });
  }
  try {
    if (transporter) {
      await transporter.sendMail({
        from: `"AXION Contact" <${process.env.GMAIL_USER}>`,
        to: process.env.ADMIN_EMAIL || process.env.GMAIL_USER,
        subject: `AXION Contact — ${name}`,
        html: `<p><b>Name:</b> ${name}</p><p><b>Email:</b> ${email}</p><p><b>Message:</b><br>${message}</p>`,
      });
    }
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to send message.' });
  }
});

// Catch-all — serve index for unknown routes
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════╗
║   AXION Backend  →  :${PORT}           ║
║   Env: ${process.env.NODE_ENV || 'development'}               ║
╚══════════════════════════════════════╝
  `);
});

module.exports = app;
