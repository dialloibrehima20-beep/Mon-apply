// server.js
require('dotenv').config();
const express = require('express');
const compression = require('compression');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsp = fs.promises;
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const crypto = require('crypto');

const app = express();
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --------- CONFIG ----------
const PORT = Number(process.env.PORT) || 3000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || 'change_this_in_prod';
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d';
const SESSION_SECRET = process.env.SESSION_SECRET || 'session_change_me';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const WHATSAPP_NUMBER = process.env.WHATSAPP_NUMBER || ''; // ex: 22390956956 (sans +)

// image quality config
const OPT_WIDTH = Number(process.env.OPT_WIDTH) || 1920;
const OPT_QUALITY = Number(process.env.OPT_QUALITY) || 85;
const THUMB_WIDTH = Number(process.env.THUMB_WIDTH) || 480;
const THUMB_QUALITY = Number(process.env.THUMB_QUALITY) || 70;

// --------- FILES & FOLDERS ----------
const ROOT = path.resolve(__dirname);
const PUBLIC_DIR = path.join(ROOT, 'public'); // frontend
const UP_DIR = path.join(ROOT, 'uploads');
const USERS_DB = path.join(ROOT, 'users.json');
const META_DB = path.join(ROOT, 'schedules.json');
const RESETS_DB = path.join(ROOT, 'password_resets.json');

if (!fs.existsSync(UP_DIR)) fs.mkdirSync(UP_DIR, { recursive: true });
if (!fs.existsSync(USERS_DB)) fs.writeFileSync(USERS_DB, '[]', 'utf8');
if (!fs.existsSync(META_DB)) fs.writeFileSync(META_DB, '[]', 'utf8');
if (!fs.existsSync(RESETS_DB)) fs.writeFileSync(RESETS_DB, '[]', 'utf8');

// ---------- IMAGE PROCESSOR ----------
let imageProcessor = null;
try {
  const sharp = require('sharp');
  imageProcessor = {
    name: 'sharp',
    async optimise(input, out) {
      await sharp(input).rotate().resize({ width: OPT_WIDTH, withoutEnlargement: true }).webp({ quality: OPT_QUALITY }).toFile(out);
    },
    async thumbnail(input, out) {
      await sharp(input).rotate().resize({ width: THUMB_WIDTH, withoutEnlargement: true }).webp({ quality: THUMB_QUALITY }).toFile(out);
    }
  };
  console.log('Image processor: sharp');
} catch (e) {
  try {
    const Jimp = require('jimp');
    imageProcessor = {
      name: 'jimp',
      async optimise(input, out) {
        const img = await Jimp.read(input);
        if (img.bitmap.width > OPT_WIDTH) img.resize(OPT_WIDTH, Jimp.AUTO);
        img.quality(OPT_QUALITY);
        await img.writeAsync(out);
      },
      async thumbnail(input, out) {
        const img = await Jimp.read(input);
        if (img.bitmap.width > THUMB_WIDTH) img.resize(THUMB_WIDTH, Jimp.AUTO);
        img.quality(THUMB_QUALITY);
        await img.writeAsync(out);
      }
    };
    console.log('Image processor: jimp (fallback)');
  } catch (err) {
    imageProcessor = {
      name: 'none',
      async optimise(input, out) { await fsp.copyFile(input, out); },
      async thumbnail(input, out) { await fsp.copyFile(input, out); }
    };
    console.warn('No image processor installed (sharp/jimp). Original files will be kept.');
  }
}

// ---------- HELPERS ----------
const readJSON = async (file) => {
  try { const raw = await fsp.readFile(file, 'utf8'); return JSON.parse(raw || '[]'); } catch { return []; }
};
const writeJSON = async (file, data) => { await fsp.writeFile(file, JSON.stringify(data, null, 2), 'utf8'); };
const sanitize = (s) => (s || '').toString().replace(/[^a-z0-9_\-\.]/gi, '_').slice(0, 140);
const makeToken = (user) => jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
const asyncHandler = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------- MULTER (uploads) ----------
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UP_DIR),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || '') || '';
    const base = path.basename(file.originalname || '', ext);
    cb(null, `${Date.now()}__${sanitize(base)}${ext.toLowerCase()}`);
  }
});
const allowed = new Set(['image/jpeg','image/jpg','image/png','image/webp','image/gif']);
function fileFilter(req, file, cb) { allowed.has(file.mimetype) ? cb(null, true) : cb(new Error('Type non supporté')); }
const upload = multer({ storage, fileFilter, limits: { fileSize: 6 * 1024 * 1024 } });

// ---------- AUTH HELPERS ----------
async function authFromHeader(req) {
  const header = req.headers['authorization'] || '';
  const m = header.match(/^Bearer (.+)$/);
  if (!m) throw new Error('No token provided');
  const token = m[1];
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { throw new Error('Invalid token'); }
  const users = await readJSON(USERS_DB);
  const user = users.find(u => u.id === payload.id);
  if (!user) throw new Error('User not found');
  return user;
}
async function authMiddleware(req, res, next) {
  try { req.user = await authFromHeader(req); next(); } catch (e) { return res.status(401).json({ ok: false, msg: e.message }); }
}
function requireRole(role) { return (req, res, next) => { if (!req.user) return res.status(401).json({ ok: false, msg: 'Not authenticated' }); if (req.user.role !== role) return res.status(403).json({ ok: false, msg: 'Forbidden' }); next(); }; }

// ---------- PASSPORT / GOOGLE ----------
app.use(session({ secret: SESSION_SECRET, resave: false, saveUninitialized: false, cookie: { secure: false } }));
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((u, done) => done(null, u.id));
passport.deserializeUser(async (id, done) => {
  try { const users = await readJSON(USERS_DB); done(null, users.find(u => u.id === id) || null); } catch (e) { done(e, null); }
});

if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
  console.log('Google OAuth keys not set (GOOGLE_CLIENT_ID/SECRET). /auth/google will fail until configured.');
}

passport.use(new GoogleStrategy({
  clientID: GOOGLE_CLIENT_ID,
  clientSecret: GOOGLE_CLIENT_SECRET,
  callbackURL: `${BASE_URL}/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const email = profile.emails?.[0]?.value;
    if (!email) return done(new Error('Google account has no email'), null);
    const users = await readJSON(USERS_DB);
    let user = users.find(u => (u.email || '').toLowerCase() === email.toLowerCase());
    if (!user) {
      user = {
        id: Date.now().toString(),
        nom: profile.name?.familyName || '',
        prenom: profile.name?.givenName || '',
        username: (profile.displayName || email.split('@')[0]).replace(/\s+/g, '_'),
        email,
        phone: null,
        passwordHash: null,
        role: 'eleve',
        ecole: null,
        createdAt: Date.now(),
        oauthProvider: 'google',
        oauthId: profile.id
      };
      users.push(user);
      await writeJSON(USERS_DB, users);
    } else {
      user.oauthProvider = 'google';
      user.oauthId = profile.id;
      await writeJSON(USERS_DB, users);
    }
    return done(null, user);
  } catch (err) { return done(err, null); }
}));

// ---------- ROUTES ----------

// serve frontend (public folder)
app.use(express.static(PUBLIC_DIR, { index: false }));

// convenience root -> serve index.html if exists
app.get('/', (req, res) => {
  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  return res.send('Emploi du temps server is up.');
});

// Google OAuth start
app.get('/auth/google', (req, res, next) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return res.status(500).send('Google OAuth not configured');
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// Google OAuth callback -> redirect to frontend with token in fragment
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), asyncHandler(async (req, res) => {
  if (!req.user) return res.redirect('/?oauth_error=1');
  const token = makeToken(req.user);
  return res.redirect(`/#token=${encodeURIComponent(token)}`);
}));

// register (json)
app.post('/api/register', asyncHandler(async (req, res) => {
  const { nom, prenom, dob, username, email, phone, password, role, ecole } = req.body || {};
  if (!nom || !prenom || !username || !email || !password || !role) return res.status(400).json({ ok: false, msg: 'Champs requis manquants' });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ ok: false, msg: 'Email invalide' });
  const users = await readJSON(USERS_DB);
  if (users.find(u => (u.email || '').toLowerCase() === email.toLowerCase())) return res.status(409).json({ ok: false, msg: 'Un compte existe déjà avec cet email' });
  if (users.find(u => (u.username || '').toLowerCase() === username.toLowerCase())) return res.status(409).json({ ok: false, msg: 'Nom d\'utilisateur déjà pris' });

  const hash = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
  const user = { id: Date.now().toString(), nom, prenom, dob: dob || null, username, email, phone: phone || null, passwordHash: hash, role, ecole: ecole || null, createdAt: Date.now() };
  users.push(user);
  await writeJSON(USERS_DB, users);
  const token = makeToken(user);
  return res.json({ ok: true, token, role: user.role, msg: 'Inscription réussie' });
}));

// login (json)
app.post('/api/login', asyncHandler(async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ ok: false, msg: 'email/password manquant' });
  const users = await readJSON(USERS_DB);
  const user = users.find(u => (u.email || '').toLowerCase() === email.toLowerCase());
  if (!user) return res.status(404).json({ ok: false, msg: 'Utilisateur non trouvé' });
  if (!user.passwordHash) return res.status(403).json({ ok: false, msg: 'Compte créé via OAuth' });
  const match = bcrypt.compareSync(password, user.passwordHash);
  if (!match) return res.status(401).json({ ok: false, msg: 'Mot de passe incorrect' });
  const token = makeToken(user);
  return res.json({ ok: true, token, role: user.role, username: user.username, id: user.id });
}));

// password reset: request token
app.post('/api/request-password-reset', asyncHandler(async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ ok: false, msg: 'Email requis' });
  const token = crypto.randomBytes(24).toString('hex');
  const resets = await readJSON(RESETS_DB);
  resets.push({ token, email, expires: Date.now() + 3600_000, used: false, createdAt: Date.now() });
  await writeJSON(RESETS_DB, resets);
  // In prod: send token by email. For now return token for testing
  return res.json({ ok: true, msg: 'Token généré', token });
}));

// reset password
app.post('/api/reset-password', asyncHandler(async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ ok: false, msg: 'token et nouveau mot de passe requis' });
  const resets = await readJSON(RESETS_DB);
  const r = resets.find(x => x.token === token);
  if (!r) return res.status(400).json({ ok: false, msg: 'Token invalide' });
  if (r.used) return res.status(400).json({ ok: false, msg: 'Token déjà utilisé' });
  if (Date.now() > r.expires) return res.status(400).json({ ok: false, msg: 'Token expiré' });
  const users = await readJSON(USERS_DB);
  const user = users.find(u => (u.email || '').toLowerCase() === (r.email || '').toLowerCase());
  if (!user) return res.status(404).json({ ok: false, msg: 'Utilisateur introuvable' });
  user.passwordHash = bcrypt.hashSync(newPassword, bcrypt.genSaltSync(10));
  r.used = true; r.usedAt = Date.now();
  await writeJSON(USERS_DB, users);
  await writeJSON(RESETS_DB, resets);
  return res.json({ ok: true, msg: 'Mot de passe réinitialisé' });
}));

// upload (maitre only)
app.post('/api/upload', asyncHandler(async (req, res) => {
  upload.array('files', 12)(req, res, async (err) => {
    if (err) return res.status(400).json({ ok: false, msg: err.message || 'Erreur upload' });
    let user;
    try { user = await authFromHeader(req); } catch (e) { return res.status(401).json({ ok: false, msg: e.message }); }
    if (user.role !== 'maitre') return res.status(403).json({ ok: false, msg: 'Forbidden: role required maitre' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ ok: false, msg: 'aucun fichier' });

    const meta = await readJSON(META_DB);
    for (const f of req.files) {
      const origPath = path.join(UP_DIR, f.filename);
      const optPath = path.join(UP_DIR, `opt_${Date.now()}__${sanitize(f.filename)}.webp`);
      const thumbPath = path.join(UP_DIR, `thumb_${Date.now()}__${sanitize(f.filename)}.webp`);
      try {
        await imageProcessor.optimise(origPath, optPath);
        await imageProcessor.thumbnail(origPath, thumbPath);
      } catch (e) {
        // fallback: copy original if processing fails
        await fsp.copyFile(origPath, optPath);
        await fsp.copyFile(origPath, thumbPath);
      }
      meta.push({
        id: Date.now().toString() + '_' + Math.floor(Math.random() * 1000),
        ecole: req.body.ecole || null,
        classe: req.body.classe || null,
        serie: req.body.serie || null,
        region: req.body.region || null,
        filename: f.filename,
        originalName: f.originalname,
        optFilename: path.basename(optPath),
        thumbFilename: path.basename(thumbPath),
        mimetype: f.mimetype,
        size: f.size,
        uploadedAt: Date.now(),
        uploaderId: user.id,
        uploaderUsername: user.username || null
      });
    }
    await writeJSON(META_DB, meta);
    return res.json({ ok: true, count: req.files.length });
  });
}));

// search public schedules
app.get('/api/schedules', asyncHandler(async (req, res) => {
  const { ecole = '', classe = '', serie = '', region = '' } = req.query || {};
  const meta = await readJSON(META_DB);
  const filt = meta.filter(m =>
    (ecole === '' || (m.ecole || '').toLowerCase().includes(ecole.toLowerCase())) &&
    (classe === '' || (m.classe || '').toLowerCase().includes(classe.toLowerCase())) &&
    (serie === '' || (m.serie || '').toLowerCase().includes(serie.toLowerCase())) &&
    (region === '' || (m.region || '').toLowerCase().includes(region.toLowerCase()))
  );
  res.json(filt);
}));

// my uploads
app.get('/api/myschedules', authMiddleware, asyncHandler(async (req, res) => {
  const meta = await readJSON(META_DB);
  const mine = meta.filter(m => m.uploaderId === req.user.id);
  res.json(mine);
}));

// download (protected) - returns optimized file if exists, with original name
app.get('/api/download/:filename', authMiddleware, asyncHandler(async (req, res) => {
  const filename = path.basename(req.params.filename || '');
  const filePath = path.join(UP_DIR, filename);
  if (!fs.existsSync(filePath)) return res.status(404).json({ ok: false, msg: 'Fichier introuvable' });
  const meta = await readJSON(META_DB);
  const item = meta.find(m => m.filename === filename);
  const sendPath = item && item.optFilename ? path.join(UP_DIR, item.optFilename) : filePath;
  const downloadName = item && item.originalName ? item.originalName : filename;
  return res.download(sendPath, downloadName, (err) => {
    if (err) console.error('download error', err);
  });
}));

// me
app.get('/api/me', authMiddleware, asyncHandler(async (req, res) => {
  const copy = Object.assign({}, req.user);
  delete copy.passwordHash;
  res.json({ ok: true, user: copy });
}));

// contact -> redirect to WhatsApp (front can also do direct link)
app.get('/contact', (req, res) => {
  if (!WHATSAPP_NUMBER) return res.status(400).send('WhatsApp number not configured');
  // ensure number has no non-digit
  const digits = WHATSAPP_NUMBER.replace(/\D/g, '');
  return res.redirect(`https://wa.me/${digits}`);
});

// serve uploads publicly for preview (thumbnails and opt)
app.use('/uploads', express.static(UP_DIR, { index: false }));

// fallback error handler
app.use((err, req, res, next) => {
  console.error(err && (err.stack || err));
  if (res.headersSent) return next(err);
  res.status(500).json({ ok: false, msg: err && err.message ? err.message : 'Erreur serveur' });
});

// start
app.listen(PORT, () => {
  console.log(`Server listening on ${BASE_URL} (port ${PORT})`);
  console.log('Google callback URL:', `${BASE_URL}/auth/google/callback`);
  console.log('Image processor:', imageProcessor.name);
});
