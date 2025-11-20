// server.js - version finale complète autonome
const express = require('express');
const compression = require('compression');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fsPromises = fs.promises;
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

// ---------------- CONFIG ----------------
const PORT = 3000;const BASE_URL = `http://192.168.100.22:3000`;
// Clés Google intégrées directement
const GOOGLE_CLIENT_ID = "REPLACE_ME";
const GOOGLE_CLIENT_SECRET = "REPLACE_ME";
const JWT_SECRET = 'une_cle_longue_changez_en_prod';
const JWT_EXPIRES = '7d';

// Image optimisation HD/pro
const OPT_WIDTH = 1920;
const OPT_QUALITY = 85;
const THUMB_WIDTH = 480;
const THUMB_QUALITY = 70;

// ---------------- FS files & folders ----------------
const ROOT = path.resolve(__dirname);
const UP_DIR = path.join(ROOT, 'uploads');
const DB_USERS = path.join(ROOT, 'users.json');
const DB_META = path.join(ROOT, 'schedules.json');
const DB_RESETS = path.join(ROOT, 'password_resets.json');

oif(!fs.existsSync(UP_DIR)) fs.mkdirSync(UP_DIR, { recursive: true });
if(!fs.existsSync(DB_USERS)) fs.writeFileSync(DB_USERS, '[]','utf8');
if(!fs.existsSync(DB_META)) fs.writeFileSync(DB_META, '[]','utf8');
if(!fs.existsSync(DB_RESETS)) fs.writeFileSync(DB_RESETS, '[]','utf8');

// ---------------- image processor ----------------
let imageProcessor;
try {
  const sharp = require('sharp');
  imageProcessor = {
    async optimise(inputPath, outPath) { await sharp(inputPath).rotate().resize({ width: OPT_WIDTH, withoutEnlargement:true }).webp({ quality: OPT_QUALITY }).toFile(outPath); },
    async thumbnail(inputPath, outPath) { await sharp(inputPath).rotate().resize({ width: THUMB_WIDTH, withoutEnlargement:true }).webp({ quality: THUMB_QUALITY }).toFile(outPath); },
    name: 'sharp'
  };
  console.log('Sharp image processing enabled');
} catch(e) {
  const Jimp = require('jimp');
  imageProcessor = {
    async optimise(inputPath, outPath) { const img = await Jimp.read(inputPath); if(img.bitmap.width>OPT_WIDTH) img.resize(OPT_WIDTH,Jimp.AUTO); img.quality(OPT_QUALITY); await img.writeAsync(outPath); },
    async thumbnail(inputPath, outPath) { const img = await Jimp.read(inputPath); if(img.bitmap.width>THUMB_WIDTH) img.resize(THUMB_WIDTH,Jimp.AUTO); img.quality(THUMB_QUALITY); await img.writeAsync(outPath); },
    name: 'jimp'
  };
  console.log('Jimp image processing fallback');
}

// ---------------- helpers ----------------
async function readJSON(file){ try{ return JSON.parse(await fsPromises.readFile(file,'utf8')||'[]'); }catch{return [];} }
async function writeJSON(file,data){ await fsPromises.writeFile(file, JSON.stringify(data,null,2),'utf8'); }
function sanitize(s){ return (s||'').toString().replace(/[^a-z0-9_\-\.]/gi,'_').slice(0,140); }
function makeToken(user){ return jwt.sign({id:user.id,role:user.role}, JWT_SECRET, {expiresIn:JWT_EXPIRES}); }
const asyncHandler = fn => (req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next);

// ---------------- multer ----------------
const storage = multer.diskStorage({
  destination:(req,file,cb)=>cb(null, UP_DIR),
  filename:(req,file,cb)=>cb(null, `${Date.now()}__${sanitize(file.originalname)}${path.extname(file.originalname)}`)
});
const allowedMime = new Set(['image/jpeg','image/jpg','image/png','image/webp','image/gif']);
function fileFilter(req,file,cb){ allowedMime.has(file.mimetype)?cb(null,true):cb(new Error('Type non supporté')); }
const upload = multer({ storage, fileFilter, limits:{ fileSize:6*1024*1024 } });

// ---------------- auth helpers ----------------
async function authFromHeader(req){
  const header = req.headers['authorization']||'';
  const m = header.match(/^Bearer (.+)$/);
  if(!m) throw new Error('No token');
  const payload = jwt.verify(m[1], JWT_SECRET);
  const users = await readJSON(DB_USERS);
  const user = users.find(u=>u.id===payload.id);
  if(!user) throw new Error('User not found');
  return user;
}
async function authMiddleware(req,res,next){ try{ req.user = await authFromHeader(req); next(); }catch(e){ res.status(401).json({ok:false,msg:e.message}); } }
function requireRole(role){ return (req,res,next)=>{ if(!req.user) return res.status(401).json({ok:false,msg:'Not authenticated'}); if(req.user.role!==role) return res.status(403).json({ok:false,msg:'Forbidden'}); next(); }; }

// ---------------- passport google ----------------
app.use(session({ secret:'session_secret', resave:false, saveUninitialized:false }));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser((u,d)=>d(null,u.id));
passport.deserializeUser(async(id,d)=>{ const users=await readJSON(DB_USERS); d(null,users.find(u=>u.id===id)||null); });

passport.use(new GoogleStrategy({
  clientID:GOOGLE_CLIENT_ID, clientSecret:GOOGLE_CLIENT_SECRET, callbackURL:`${BASE_URL}/auth/google/callback`
}, async (token, refreshToken, profile, done)=>{
  try{
    const email = profile.emails?.[0]?.value; if(!email) return done(new Error('No email'),null);
    const users = await readJSON(DB_USERS);
    let user = users.find(u=>(u.email||'').toLowerCase()===email.toLowerCase());
    if(!user){ user={id:Date.now().toString(), nom:profile.name.familyName||'', prenom:profile.name.givenName||'', username:(profile.displayName||email.split('@')[0]).replace(/\s+/g,'_'), email, passwordHash:null, role:'eleve', createdAt:Date.now(), oauthProvider:'google', oauthId:profile.id}; users.push(user); await writeJSON(DB_USERS,users); }
    else{ user.oauthProvider='google'; user.oauthId=profile.id; await writeJSON(DB_USERS,users); }
    done(null,user);
  }catch(e){ done(e,null); }
}));

// ---------------- ROUTES ----------------
app.get('/auth/google', passport.authenticate('google',{scope:['profile','email']}));
app.get('/auth/google/callback', passport.authenticate('google',{failureRedirect:'/'}), asyncHandler(async(req,res)=>{ const token = makeToken(req.user); res.redirect(`/#token=${token}`); }));

app.post('/api/register', asyncHandler(async(req,res)=>{
  const {nom,prenom,username,email,password,role} = req.body||{};
  if(!nom||!prenom||!username||!email||!password||!role) return res.status(400).json({ok:false,msg:'Champs manquants'});
  const users = await readJSON(DB_USERS);
  if(users.find(u=>(u.email||'').toLowerCase()===email.toLowerCase())) return res.status(409).json({ok:false,msg:'Email existant'});
  if(users.find(u=>(u.username||'').toLowerCase()===username.toLowerCase())) return res.status(409).json({ok:false,msg:'Nom utilisateur existant'});
  const hash = bcrypt.hashSync(password,bcrypt.genSaltSync(10));
  const user={id:Date.now().toString(), nom, prenom, username, email, passwordHash:hash, role, createdAt:Date.now()};
  users.push(user); await writeJSON(DB_USERS,users);
  const token = makeToken(user); res.json({ok:true,token,role:user.role});
}));

app.post('/api/login', asyncHandler(async(req,res)=>{
  const {email,password} = req.body||{};
  if(!email||!password) return res.status(400).json({ok:false,msg:'email/password manquant'});
  const users=await readJSON(DB_USERS);
  const user=users.find(u=>(u.email||'').toLowerCase()===email.toLowerCase());
  if(!user) return res.status(404).json({ok:false,msg:'Utilisateur non trouvé'});
  if(!user.passwordHash) return res.status(403).json({ok:false,msg:'Compte OAuth'});
  if(!bcrypt.compareSync(password,user.passwordHash)) return res.status(401).json({ok:false,msg:'Mot de passe incorrect'});
  const token = makeToken(user); res.json({ok:true,token,role:user.role,username:user.username,id:user.id});
}));

app.post('/api/request-password-reset', asyncHandler(async(req,res)=>{
  const {email}=req.body||{};
  if(!email) return res.status(400).json({ok:false,msg:'Email requis'});
  const token=crypto.randomBytes(24).toString('hex');
  const resets=await readJSON(DB_RESETS);
  resets.push({token,email,expires:Date.now()+3600000,used:false,createdAt:Date.now()});
  await writeJSON(DB_RESETS,resets);
  res.json({ok:true,msg:'Token généré', token}); // pour test
}));

app.post('/api/reset-password', asyncHandler(async(req,res)=>{
  const {token,newPassword}=req.body||{};
  if(!token||!newPassword) return res.status(400).json({ok:false,msg:'token et nouveau mot de passe requis'});
  const resets=await readJSON(DB_RESETS);
  const r=resets.find(x=>x.token===token);
  if(!r) return res.status(400).json({ok:false,msg:'Token invalide'});
  if(r.used) return res.status(400).json({ok:false,msg:'Token déjà utilisé'});
  if(Date.now()>r.expires) return res.status(400).json({ok:false,msg:'Token expiré'});
  const users=await readJSON(DB_USERS);
  const user=users.find(u=>(u.email||'').toLowerCase()===(r.email||'').toLowerCase());
  if(!user) return res.status(404).json({ok:false,msg:'Utilisateur introuvable'});
  user.passwordHash=bcrypt.hashSync(newPassword,bcrypt.genSaltSync(10));
  r.used=true; r.usedAt=Date.now();
  await writeJSON(DB_USERS,users);
  await writeJSON(DB_RESETS,resets);
  res.json({ok:true,msg:'Mot de passe réinitialisé'});
}));

app.post('/api/upload', asyncHandler(async(req,res)=>{
  upload.array('files',12)(req,res,async(err)=>{
    if(err) return res.status(400).json({ok:false,msg:err.message});
    let user; try{ user=await authFromHeader(req); }catch(e){ return res.status(401).json({ok:false,msg:e.message}); }
    if(user.role!=='maitre') return res.status(403).json({ok:false,msg:'Forbidden: maitre only'});
    if(!req.files||req.files.length===0) return res.status(400).json({ok:false,msg:'Aucun fichier'});
    const meta=await readJSON(DB_META);
    for(const f of req.files){
      const origPath=path.join(UP_DIR,f.filename);
      const optPath=path.join(UP_DIR,`opt_${Date.now()}__${sanitize(f.filename)}.webp`);
      const thumbPath=path.join(UP_DIR,`thumb_${Date.now()}__${sanitize(f.filename)}.webp`);
      await imageProcessor.optimise(origPath,optPath);
      await imageProcessor.thumbnail(origPath,thumbPath);
      meta.push({id:Date.now().toString(), filename:f.filename, originalName:f.originalname, optFilename:path.basename(optPath), thumbFilename:path.basename(thumbPath), uploadedAt:Date.now(), uploaderId:user.id, uploaderUsername:user.username});
    }
    await writeJSON(DB_META,meta);
    res.json({ok:true,count:req.files.length});
  });
}));

app.get('/api/schedules', asyncHandler(async(req,res)=>{
  const {ecole='',classe='',serie='',region=''}=req.query||{};
  const meta=await readJSON(DB_META);
  const filt=meta.filter(m=> (ecole===''||(m.ecole||'').toLowerCase().includes(ecole.toLowerCase())) && (classe===''||(m.classe||'').toLowerCase().includes(classe.toLowerCase())) && (serie===''||(m.serie||'').toLowerCase().includes(serie.toLowerCase())) && (region===''||(m.region||'').toLowerCase().includes(region.toLowerCase())));
  res.json(filt);
}));

app.use('/uploads',express.static(UP_DIR,{index:false}));
app.get('/',(req,res)=>{ const indexPath=path.join(ROOT,'index.html'); if(fs.existsSync(indexPath)) return res.sendFile(indexPath); res.send('Server running'); });

app.listen(PORT,()=>{ console.log(`Server running on ${BASE_URL}, Google callback: ${BASE_URL}/auth/google/callback, Image processor: ${imageProcessor.name}`); });
