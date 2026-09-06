const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const crypto = require('crypto');
try { require('dotenv').config(); } catch {} // Load .env if available
let firebaseAdmin = null;
let firebaseInitAttempted = false;
function initFirebase() {
  if (firebaseInitAttempted) return;
  firebaseInitAttempted = true;
  try {
    const serviceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH || './firebase-service-account.json';
    if (require('fs').existsSync(serviceAccountPath)) {
      firebaseAdmin = require('firebase-admin');
      const serviceAccount = require(serviceAccountPath);
      firebaseAdmin.initializeApp({ credential: firebaseAdmin.credential.cert(serviceAccount) });
      console.log('  ✅ Firebase Admin SDK initialized');
    } else {
      console.log('  ⚠️  Firebase: no service account file at', serviceAccountPath);
    }
  } catch (e) {
    console.log('  ⚠️  Firebase Admin not available:', e.message);
  }
}
const { Registro, Log, Solicitante, MigracionPendiente, MobileDevice, AuthRequest } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://malegre_db_user:gKHctbCg9KcYUrO8@cluster0.m5bntoj.mongodb.net/';
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_EXPIRY = '5d'; // Tokens de 5 días según requerimiento
const MIGRATION_IMPORT_KEY = process.env.PLACETAID_MIGRATION_KEY || '';
const ADMIN_DESKTOP_CLIENT_ID = process.env.PLACETAID_ADMIN_DESKTOP_CLIENT_ID || 'administracion-gdlp';
const ADMIN_DESKTOP_CALLBACK = process.env.PLACETAID_ADMIN_DESKTOP_CALLBACK || 'http://127.0.0.1:18731/callback';
const BUILTIN_PENDING_MIGRATIONS = [
  {
    dip: '20521220S',
    placeid: 'PLID-20521220S',
    nombre: 'Miembro',
    apellidos: 'GDLP',
    origen: 'migracion_gdlp'
  }
];
const DESKTOP_CLIENT_ID = 'placetaid-desktop';
const DESKTOP_CALLBACK = 'placetaid-desktop://auth';

const BUILTIN_SOLICITANTES = [
  {
    nombre: 'Administracion GDLP',
    descripcion: 'Aplicacion de escritorio oficial para administracion bancaria y PlacetaID.',
    plataforma: 'desktop',
    urlOrigen: ADMIN_DESKTOP_CALLBACK,
    redirectUris: [ADMIN_DESKTOP_CALLBACK],
    apiKey: ADMIN_DESKTOP_CLIENT_ID,
    activo: true,
    pkceRequired: false,
    permitirWebFallback: false
  },
  {
    nombre: 'PlacetaID Desktop',
    descripcion: 'Aplicacion de escritorio para autenticacion sin movil.',
    plataforma: 'desktop',
    urlOrigen: DESKTOP_CALLBACK,
    redirectUris: [DESKTOP_CALLBACK],
    apiKey: DESKTOP_CLIENT_ID,
    activo: true,
    pkceRequired: false,
    permitirWebFallback: true
  },
  {
    nombre: 'GDLP CRM Web',
    descripcion: 'Portal web del CRM del Grupo de La Placeta.',
    plataforma: 'web',
    urlOrigen: 'https://gdlp.laplaceta.org/placetid/callback',
    redirectUris: [
      'https://gdlp.laplaceta.org/placetid/callback',
      'https://www.laplaceta.org/placetid/callback',
      'https://grupodelaplaceta.vercel.app/placetid/callback',
      'http://localhost:3001/placetid/callback'
    ],
    apiKey: process.env.PLACETAID_CRM_CLIENT_ID || 'ccb611655030bdadf7218418dc195dcb',
    activo: true,
    pkceRequired: false,
    permitirWebFallback: true
  },
  {
    nombre: 'Banco Web',
    descripcion: 'Portal web del Banco de La Placeta.',
    plataforma: 'web',
    urlOrigen: 'https://banco.laplaceta.org/',
    redirectUris: [
      'https://banco.laplaceta.org/',
      'http://localhost:3000/'
    ],
    apiKey: process.env.PLACETAID_BANCO_CLIENT_ID || 'banco-web',
    activo: true,
    pkceRequired: false,
    permitirWebFallback: true
  },
  {
    nombre: 'Voley Club La Placeta',
    descripcion: 'Web y area del jugador del Voley Club La Placeta.',
    plataforma: 'web',
    urlOrigen: 'https://vclaplaceta.vercel.app/',
    redirectUris: [
      'https://vclaplaceta.vercel.app/auth/callback.html',
      'http://localhost:3000/auth/callback.html'
    ],
    apiKey: process.env.PLACETAID_VOLEY_CLIENT_ID || 'voley-club',
    activo: true,
    pkceRequired: false,
    permitirWebFallback: true
  },
  {
    nombre: 'Placeta Joven (joven.laplaceta.org)',
    descripcion: 'Web oficial del programa Placeta Joven: ventajas y suscripcion para jovenes de 16 a 30 anos.',
    plataforma: 'web',
    urlOrigen: 'https://joven.laplaceta.org/auth/callback.html',
    redirectUris: [
      'https://joven.laplaceta.org/auth/callback.html',
      'https://joven.laplaceta.org/',
      'https://placetajoven.vercel.app/auth/callback.html',
      'http://localhost:3000/auth/callback.html'
    ],
    apiKey: process.env.PLACETAID_JOVEN_CLIENT_ID || 'placetajoven-web',
    logo: 'https://joven.laplaceta.org/img/jovenlogo.png',
    bgColor: '#2A0750',
    activo: true,
    pkceRequired: true,
    permitirWebFallback: true
  }
];

// ── MIDDLEWARE ────────────────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Helper para obtener IP en producción
const getClientIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || 'unknown';
};

// Rate limiting global
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: getClientIP
});
app.use('/api/', limiter);

// Rate limiting estricto en autenticación
const authLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: { error: 'Demasiados intentos. Espera 10 minutos.' },
  keyGenerator: getClientIP
});
app.use('/api/auth/', authLimiter);

// ── MONGODB ───────────────────────────────────────────────────────────────────
let isConnected = false;

// ── Caché en memoria ─────────────────────────────────────────────────────────
const cache = {
  solicitantes: new Map(), // apiKey -> { info, expiresAt }
  SOLICITANTE_TTL: 60_000 // 1 minuto
};

function getCachedSolicitante(apiKey) {
  const entry = cache.solicitantes.get(apiKey);
  if (entry && entry.expiresAt > Date.now()) return entry.info;
  return null;
}

function setCachedSolicitante(apiKey, info) {
  cache.solicitantes.set(apiKey, { info, expiresAt: Date.now() + cache.SOLICITANTE_TTL });
}

function invalidateSolicitanteCache(apiKey) {
  cache.solicitantes.delete(apiKey);
}

let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;

async function connectToDatabase() {
  // Si ya estamos conectados realmente, salir
  if (isConnected && mongoose.connection.readyState === 1) return;
  // Si la bandera dice connected pero la conexión real está muerta, resetear
  if (isConnected && mongoose.connection.readyState !== 1) {
    isConnected = false;
    cache.solicitantes.clear();
  }

  try {
    console.log('🔌 MongoDB connection attempt...');

    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
      socketTimeoutMS: 60000,
      connectTimeoutMS: 15000,
      maxPoolSize: 10,
      minPoolSize: 1,
      maxIdleTimeMS: 30000,
      heartbeatFrequencyMS: 10000
    });

    isConnected = true;
    reconnectAttempts = 0;
    console.log(`✅ MongoDB conectado`);

    // Drop legacy non-sparse supportNumber index so mongoose can recreate it as sparse
    try {
      await mongoose.connection.db.collection('registros').dropIndex('supportNumber_1');
      console.log('Dropped old non-sparse supportNumber_1 index');
    } catch (e) {
      // Index did not exist or was already dropped, which is fine
    }

    // Operaciones post-conexión en paralelo y sin bloquear el arranque
    Promise.all([
      backfillSupportNumbers(),
      ensureBuiltinPendingMigrations(),
      ensureBuiltinSolicitantes()
    ]).catch(err => console.error('Error en operaciones post-conexión:', err.message));
  } catch (err) {
    console.error('❌ Error MongoDB:', err.message);
    isConnected = false;
    if (reconnectAttempts < MAX_RECONNECT_ATTEMPTS) {
      reconnectAttempts++;
      const delay = Math.min(1000 * Math.pow(2, reconnectAttempts), 30000);
      console.log(`⏳ Reintento ${reconnectAttempts}/${MAX_RECONNECT_ATTEMPTS} en ${delay}ms...`);
      await new Promise(r => setTimeout(r, delay));
      return connectToDatabase();
    }
    throw err;
  }
}

// Reconexión automática en caso de pérdida de conexión
mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB desconectado. Intentando reconectar...');
  isConnected = false;
  // Limpiar cachés al perder conexión
  cache.solicitantes.clear();
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconectado');
  isConnected = true;
});

mongoose.connection.on('error', (err) => {
  console.error('❌ Error de conexión MongoDB:', err.message);
  isConnected = false;
});

// Middleware para asegurar conexión BD (non-blocking si ya conectado)
app.use(async (req, res, next) => {
  // Verificar estado real de la conexión (mongoose.readyState: 0=disconnected, 1=connected, 2=connecting)
  const connReady = mongoose.connection.readyState === 1;
  if (isConnected && connReady) return next();
  // Si isConnected es true pero la conexión real está muerta (caso Vercel serverless), resetear
  if (isConnected && !connReady) {
    isConnected = false;
    cache.solicitantes.clear();
  }
  try {
    await connectToDatabase();
    next();
  } catch (err) {
    res.status(503).json({ error: 'Database connection failed', detail: err.message });
  }
});

// ── HELPERS ───────────────────────────────────────────────────────────────────
function getIP(req) {
  return getClientIP(req);
}

async function registrarLog(data) {
  try {
    await Log.create(data);
  } catch (e) {
    console.error('Error guardando log:', e);
  }
}

async function ensureBuiltinPendingMigrations() {
  for (const item of BUILTIN_PENDING_MIGRATIONS) {
    await MigracionPendiente.updateOne(
      { dip: item.dip },
      {
        $setOnInsert: {
          dip: item.dip,
          placeid: item.placeid,
          nombre: item.nombre,
          apellidos: item.apellidos,
          origen: item.origen,
          estado: 'pendiente',
          creadoEn: new Date()
        }
      },
      { upsert: true }
    );
  }
}

async function ensureBuiltinSolicitantes() {
  for (const item of BUILTIN_SOLICITANTES) {
    await Solicitante.updateOne(
      { apiKey: item.apiKey },
      {
        $set: {
          nombre: item.nombre,
          descripcion: item.descripcion,
          plataforma: item.plataforma,
          urlOrigen: item.urlOrigen,
          redirectUris: item.redirectUris,
          activo: item.activo,
          pkceRequired: item.pkceRequired,
          permitirWebFallback: item.permitirWebFallback,
          ...(item.logo ? { logo: item.logo } : {}),
          ...(item.bgColor ? { bgColor: item.bgColor } : {})
        },
        $setOnInsert: {
          apiKey: item.apiKey,
          creadoEn: new Date()
        }
      },
      { upsert: true }
    );
  }
}

async function findActiveSolicitante(apiKey) {
  const key = String(apiKey || '').trim();
  if (!key) return null;

  // Intentar caché primero
  const cached = getCachedSolicitante(key);
  if (cached) return cached;

  const dbSolicitante = await Solicitante.findOne({ apiKey: key, activo: true });
  if (dbSolicitante) {
    setCachedSolicitante(key, dbSolicitante);
    return dbSolicitante;
  }

  const builtin = BUILTIN_SOLICITANTES.find(item => item.apiKey === key && item.activo);
  if (builtin) setCachedSolicitante(key, builtin);
  return builtin || null;
}

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
  const token = auth.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;

    // Renovación automática: si el token tiene más de 1 día, emitimos uno nuevo en el header
    const now = Math.floor(Date.now() / 1000);
    if (decoded.iat && (now - decoded.iat) > 24 * 60 * 60) {
      const newToken = jwt.sign(
        {
          registroId: decoded.registroId,
          dip: decoded.dip,
          rol: decoded.rol,
          nombre: decoded.nombre,
          apellidos: decoded.apellidos,
          nombreCompleto: decoded.nombreCompleto,
          edad: decoded.edad,
          accesoComo: decoded.accesoComo
        },
        JWT_SECRET,
        { expiresIn: JWT_EXPIRY }
      );
      res.setHeader('X-New-Token', newToken);
      res.setHeader('Access-Control-Expose-Headers', 'X-New-Token');
    }

    next();
  } catch (err) {
    console.log('JWT Error:', err.message);
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user?.rol !== 'administrador') return res.status(403).json({ error: 'Acceso restringido a administradores' });
  next();
}

// Middleware: permite acceso admin via X-API-Key (para CRM)
const CRM_API_KEY = 'ccb611655030bdadf7218418dc195dcb';
const ADMIN_API_KEYS = new Set(
  (process.env.PLACETAID_ADMIN_KEYS || `${ADMIN_DESKTOP_CLIENT_ID},${CRM_API_KEY}`)
    .split(',').map(k => k.trim()).filter(Boolean)
);

function verifyAdminApiKey(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (apiKey && ADMIN_API_KEYS.has(apiKey)) {
    req.user = { rol: 'administrador', apiKey: true };
    return next();
  }
  verifyToken(req, res, next);
}

function normalizeRedirectUris(urlOrigen, redirectUris = []) {
  const raw = [
    urlOrigen,
    ...(Array.isArray(redirectUris) ? redirectUris : String(redirectUris || '').split('\n'))
  ];
  const unique = new Set();

  raw
    .map(value => String(value || '').trim())
    .filter(Boolean)
    .forEach(value => unique.add(value));

  return [...unique];
}

function isAllowedCallback(uri, allowedUris = []) {
  if (!uri) return false;
  return allowedUris.some(allowed => String(allowed).trim() === String(uri).trim());
}

function platformLabel(platform) {
  const labels = {
    web: 'Web',
    android: 'Android',
    ios: 'iOS',
    desktop: 'Escritorio',
    backend: 'Backend',
    multiplataforma: 'Multiplataforma'
  };
  return labels[platform] || 'Web';
}

function normalizeDip(value) {
  return String(value || '').trim().toUpperCase().replace(/[\s-]+/g, '');
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function normalizePlaceId(value) {
  return String(value || '').trim().toUpperCase();
}

function buildTotpUrl(dip, secret) {
  const label = encodeURIComponent(`PlacetaID:${dip}`);
  const issuer = encodeURIComponent('Grupo de La Placeta');
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${issuer}`;
}

async function generateUniqueSupportNumber() {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const candidate = String(crypto.randomInt(10000000, 100000000));
    if (!(await Registro.exists({ supportNumber: candidate }))) return candidate;
  }
  throw new Error('No se pudo generar un número de soporte único');
}

async function backfillSupportNumbers() {
  try {
    const pendientes = await Registro.countDocuments({
      $or: [
        { supportNumber: { $exists: false } },
        { supportNumber: null }
      ]
    });

    if (pendientes === 0) return;
    console.log(`📋 Backfilling support numbers para ${pendientes} usuarios...`);

    // Procesar en lotes eficientes
    const BATCH_SIZE = 20;
    let processed = 0;

    while (processed < pendientes) {
      const batch = await Registro.find({
        $or: [
          { supportNumber: { $exists: false } },
          { supportNumber: null }
        ]
      }).limit(BATCH_SIZE);

      if (batch.length === 0) break;

      for (const user of batch) {
        try {
          user.supportNumber = await generateUniqueSupportNumber();
          await user.save();
        } catch (err) {
          console.warn(`   ⚠️ Error backfilling ${user.dip || user._id}: ${err.message?.slice(0, 80)}`);
        }
      }

      processed += batch.length;
      console.log(`   Backfilled ${processed}/${pendientes} usuarios`);
    }
  } catch (err) {
    console.error('Error backfilling support numbers:', err);
  }
}

const DEMO_USER = {
  dip: '11111111D',
  password: 'Demo1234!',
  placeid: 'PLID-DEMO',
  correo: 'demo@placeta.local',
  nombre: 'Usuario',
  apellidos: 'Demo',
  fechaNacimiento: new Date('1995-01-01'),
  rol: 'miembro',
  supportNumber: '11111111'
};

function isDemoLogin(dip, password) {
  return normalizeDip(dip) === DEMO_USER.dip && password === DEMO_USER.password;
}

async function ensureDemoRegistration() {
  const passwordHash = await bcrypt.hash(DEMO_USER.password, 12);
  const existing = await Registro.findOne({ dip: DEMO_USER.dip });

  if (existing) {
    existing.placeid = existing.placeid || DEMO_USER.placeid;
    existing.correo = existing.correo || DEMO_USER.correo;
    existing.nombre = existing.nombre || DEMO_USER.nombre;
    existing.apellidos = existing.apellidos || DEMO_USER.apellidos;
    existing.fechaNacimiento = existing.fechaNacimiento || DEMO_USER.fechaNacimiento;
    existing.rol = existing.rol || DEMO_USER.rol;
    existing.passwordHash = passwordHash;
    existing.totpSecret = existing.totpSecret || speakeasy.generateSecret({ name: `PlacetaID:${DEMO_USER.dip}`, issuer: 'Grupo de La Placeta', length: 20 }).base32;
    existing.totpVerified = false;
    existing.twoFactorDisabled = true;
    existing.bloqueado = false;
    existing.intentosFallidos = 0;
    existing.activo = true;
    await existing.save();
    return existing;
  }

  const totp = speakeasy.generateSecret({ name: `PlacetaID:${DEMO_USER.dip}`, issuer: 'Grupo de La Placeta', length: 20 });
  return Registro.create({
    ...DEMO_USER,
    passwordHash,
    totpSecret: totp.base32,
    totpVerified: false,
    twoFactorDisabled: true
  });
}

function publicRegistroData(registro) {
  const datosRegistro = {
    dip: registro.dip || null,
    placeid: registro.placeid,
    correo: registro.correo,
    nombre: registro.nombre,
    apellidos: registro.apellidos,
    nombreCompleto: registro.rol === 'empresa' ? registro.empresaNombre : `${registro.nombre} ${registro.apellidos}`.trim(),
    edad: registro.edad,
    rol: registro.rol,
    accesoComo: registro.rol === 'empresa' ? 'empresa' : 'persona',
    supportNumber: registro.supportNumber,
    points: registro.points || 0,
    banned: registro.banned || registro.bloqueado || false,
    bannedUntil: registro.bannedUntil || null,
    socialLoginType: registro.socialLoginType || null,
    socialLoginId: registro.socialLoginId || null
  };

  if (registro.rol === 'empresa') {
    datosRegistro.empresaNombre = registro.empresaNombre;
    datosRegistro.propietarios = registro.propietarios;
  }

  return datosRegistro;
}

async function completeLogin(registro, payload, req, fase = 'completa') {
  const ip = getIP(req);
  const ua = req.headers['user-agent'];

  if (!registro.supportNumber) {
    try {
      registro.supportNumber = await generateUniqueSupportNumber();
      console.log(`On-the-fly backfilled support number ${registro.supportNumber} for user ${registro.nombre} during login`);
    } catch (err) {
      console.error('Error generating unique support number on the fly:', err);
    }
  }

  registro.intentosFallidos = 0;
  registro.ultimoAcceso = new Date();
  await registro.save();

  await registrarLog({ dip: registro.dip || registro.supportNumber, registroId: registro._id, servicio: payload.servicio, servicioUrl: payload.servicioUrl, evento: 'intento_exitoso', ip, ua, fase });

  const datosRegistro = publicRegistroData(registro);
  const tokenSesion = jwt.sign(
    {
      registroId: registro._id.toString(),
      dip: registro.dip || null,
      rol: registro.rol,
      nombre: datosRegistro.nombre,
      apellidos: datosRegistro.apellidos,
      nombreCompleto: datosRegistro.nombreCompleto,
      edad: datosRegistro.edad,
      accesoComo: datosRegistro.accesoComo,
      supportNumber: datosRegistro.supportNumber,
      points: datosRegistro.points,
      banned: datosRegistro.banned,
      bannedUntil: datosRegistro.bannedUntil
    },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY }
  );

  return {
    ok: true,
    tokenSesion,
    registro: datosRegistro,
    servicio: payload.servicio,
    servicioUrl: payload.servicioUrl || null,
    plataforma: payload.platform || 'web',
    state: payload.state || null,
    expiresIn: 5 * 24 * 60 * 60,
    requiere2fa: false
  };
}

function newPlaceIdForDip(dip) {
  return `PLID-${normalizeDip(dip)}`;
}

function requireMigrationImport(req, res, next) {
  if (!MIGRATION_IMPORT_KEY) return next();
  const key = req.headers['x-migration-key'] || req.headers['x-api-key'];
  if (key !== MIGRATION_IMPORT_KEY) return res.status(401).json({ error: 'migration_key_required' });
  next();
}

async function registrationQrResponse(registro, mensaje = 'QR de Authenticator recuperado.') {
  const otpauthUrl = buildTotpUrl(registro.dip, registro.totpSecret);
  const qrCode = await QRCode.toDataURL(otpauthUrl);
  return {
    ok: true,
    dip: registro.dip,
    placeid: registro.placeid,
    correo: registro.correo,
    totpSecret: registro.totpSecret,
    qrCode,
    otpauthUrl,
    migradoDesdePendiente: Boolean(registro.migradoDesdePendiente),
    mensaje
  };
}

function getDipInitial(nombre) {
  const normalized = String(nombre || '')
    .trim()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toUpperCase();
  return normalized.match(/[A-Z]/)?.[0] || '';
}

function validateDipForName(dip, nombre) {
  if (!/^\d{8}[A-Z]$/.test(dip)) {
    const error = new Error('El DIP debe tener formato DNI: 8 dígitos y la inicial del nombre');
    error.statusCode = 400;
    throw error;
  }

  const expectedInitial = getDipInitial(nombre);
  if (expectedInitial && dip.slice(-1) !== expectedInitial) {
    const error = new Error(`La letra del DIP debe ser la inicial del nombre (${expectedInitial})`);
    error.statusCode = 400;
    throw error;
  }
}

async function generateUniqueDip(nombre) {
  const initial = getDipInitial(nombre);
  if (!initial) {
    const error = new Error('El nombre debe empezar por una letra para generar el DIP');
    error.statusCode = 400;
    throw error;
  }

  for (let attempt = 0; attempt < 20; attempt += 1) {
    const candidate = `${String(crypto.randomInt(0, 100000000)).padStart(8, '0')}${initial}`;
    if (!(await Registro.exists({ dip: candidate }))) return candidate;
  }
  throw new Error('No se pudo generar DIP único');
}

async function createPlacetaIdRegistration(payload, context = {}) {
  const { dip, nombre, apellidos, fechaNacimiento, rol, password, empresaNombre, empresaCIF, propietarios } = payload;
  const cleanRol = rol || 'miembro';
  const cleanDip = normalizeDip(dip) || await generateUniqueDip(nombre);
  const pendingMigration = await MigracionPendiente.findOne({ dip: cleanDip, estado: 'pendiente' });
  const requestedPlaceId = payload.placeid || payload.placeId || payload.place_id || payload.placetaId;
  const cleanPlaceId = normalizePlaceId(pendingMigration?.placeid || requestedPlaceId || cleanDip);
  const cleanCorreo = normalizeEmail(payload.correo || payload.email);

  if (!cleanDip || !nombre || !password) {
    const error = new Error('DIP, nombre y contraseña son requeridos');
    error.statusCode = 400;
    throw error;
  }
  if (cleanCorreo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleanCorreo)) {
    const error = new Error('Correo inválido');
    error.statusCode = 400;
    throw error;
  }
  if (cleanRol === 'empresa') {
    if (!empresaNombre || !Array.isArray(propietarios) || propietarios.length === 0) {
      const error = new Error('Las empresas deben incluir nombre de la empresa y al menos un propietario con placetaId y porcentaje');
      error.statusCode = 400;
      throw error;
    }
  } else if (!apellidos || !fechaNacimiento) {
    const error = new Error('Apellidos y fecha de nacimiento son requeridos para registros personales');
    error.statusCode = 400;
    throw error;
  }
  if (!pendingMigration) validateDipForName(cleanDip, nombre);

  const existe = await Registro.findOne({ dip: cleanDip });
  if (existe) {
    const error = new Error('El DIP ya está registrado');
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const totp = speakeasy.generateSecret({ name: `PlacetaID:${cleanDip}`, issuer: 'Grupo de La Placeta', length: 20 });
  const supportNumber = await generateUniqueSupportNumber();
  const registroData = {
    dip: cleanDip,
    placeid: cleanPlaceId,
    correo: cleanCorreo || undefined,
    nombre: String(nombre).trim(),
    rol: cleanRol,
    passwordHash,
    totpSecret: totp.base32,
    totpVerified: false,
    supportNumber
  };

  if (cleanRol === 'empresa') {
    registroData.empresaNombre = String(empresaNombre).trim();
    if (empresaCIF) registroData.empresaCIF = String(empresaCIF).trim().toUpperCase();
    registroData.propietarios = propietarios.map(owner => ({
      nombre: owner.nombre?.trim() || '',
      apellidos: owner.apellidos?.trim(),
      placetaId: owner.placetaId?.toUpperCase().trim(),
      porcentaje: owner.porcentaje
    }));
  } else {
    registroData.apellidos = String(apellidos).trim();
    registroData.fechaNacimiento = new Date(fechaNacimiento);
  }

  const registro = await Registro.create(registroData);
  if (pendingMigration) {
    pendingMigration.estado = 'migrado';
    pendingMigration.registroId = registro._id;
    pendingMigration.migradoEn = new Date();
    await pendingMigration.save();
    registro.migradoDesdePendiente = true;
    await registro.save();
  }
  await registrarLog({
    dip: registro.dip,
    registroId: registro._id,
    servicio: context.servicio || 'PlacetaID',
    servicioUrl: context.servicioUrl,
    evento: 'registro_creado',
    ip: context.ip,
    ua: context.ua,
    fase: 'completa',
    metadatos: {
      ...context.metadatos,
      migracionPendiente: Boolean(pendingMigration),
      placeidAnterior: pendingMigration?.placeidAnterior
    }
  });

  const otpauthUrl = totp.otpauth_url || buildTotpUrl(registro.dip, totp.base32);
  const qrUrl = await QRCode.toDataURL(otpauthUrl);
  return {
    ok: true,
    dip: registro.dip,
    placeid: registro.placeid,
    supportNumber: registro.supportNumber,
    correo: registro.correo,
    nombre: registro.nombre,
    apellidos: registro.apellidos,
    nombreCompleto: registro.rol === 'empresa' ? registro.empresaNombre : `${registro.nombre} ${registro.apellidos}`.trim(),
    rol: registro.rol,
    migradoDesdePendiente: Boolean(registro.migradoDesdePendiente),
    totpSecret: totp.base32,
    qrCode: qrUrl,
    otpauthUrl,
    mensaje: 'Registro creado. Escanea el QR con tu autenticador y verifica el primer código.'
  };
}

// ── API: AUTENTICACIÓN ────────────────────────────────────────────────────────

app.get('/api/auth/session', verifyToken, async (req, res) => {
  try {
    const registro = await Registro.findById(req.user.registroId);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    if (!registro.activo || registro.bloqueado) return res.status(403).json({ error: 'Registro no activo' });
    res.json({ ok: true, registro: publicRegistroData(registro) });
  } catch (err) {
    res.status(500).json({ error: 'Error al validar sesión' });
  }
});

// ⚠️ DEV-ONLY: indica al front si el bypass temporal de desarrollo está activo.
// Activar únicamente en desarrollo con: PLACETAID_DEV_BYPASS_DIP=<dip>. Sin la
// variable, esto siempre devuelve { enabled:false } y no afecta a producción.
app.get('/api/dev/bypass', async (req, res) => {
  const dip = (process.env.PLACETAID_DEV_BYPASS_DIP || '').trim();
  res.json({ enabled: !!dip, dip });
});

// ⚠️ DEV-ONLY: autoriza una solicitud de PlacetaID Móvil sin la app (solo
// cuando PLACETAID_DEV_BYPASS_DIP está fijado y coincide con el DIP).
app.post('/api/dev/movil-bypass', async (req, res) => {
  const devDip = (process.env.PLACETAID_DEV_BYPASS_DIP || '').trim();
  if (!devDip) return res.status(403).json({ error: 'dev_no_habilitado' });
  const { requestId, dip } = req.body || {};
  if (!requestId || !dip) return res.status(400).json({ error: 'requestId y dip requeridos' });
  const cleanDip = normalizeDip(dip);
  if (cleanDip !== devDip) return res.status(403).json({ error: 'dev_no_permitido' });
  try {
    const authReq = await AuthRequest.findById(requestId);
    if (!authReq) return res.status(404).json({ error: 'Solicitud no encontrada' });
    if (authReq.dip !== cleanDip) return res.status(403).json({ error: 'No corresponde a este DIP' });
    if (authReq.estado !== 'pending') return res.status(400).json({ error: 'Solicitud ya procesada: ' + authReq.estado });
    if (authReq.expiraEn < new Date()) { authReq.estado = 'expired'; await authReq.save(); return res.status(400).json({ error: 'Solicitud expirada' }); }
    authReq.estado = 'authorized';
    authReq.autorizadoEn = new Date();
    await authReq.save();
    await registrarLog({
      dip: cleanDip, registroId: (await Registro.findOne({ dip: cleanDip }))?._id,
      servicio: authReq.servicio, servicioUrl: authReq.servicioUrl, evento: 'bypass_dev_usado',
      ip: getIP(req), ua: req.headers['user-agent'], fase: 'móvil',
      metadatos: { tipo: 'dev_movil_bypass', requestId: authReq._id.toString() }
    });
    res.json({ ok: true, estado: 'authorized' });
  } catch (err) {
    res.status(500).json({ error: 'Error al procesar solicitud' });
  }
});

// FASE 1: DIP + Contraseña
app.post('/api/auth/fase1', async (req, res) => {
  const { dip, password, servicio, servicioUrl, clientId, platform, state: oauthState, codeChallenge } = req.body;
  if (!dip || !password) return res.status(400).json({ error: 'DIP y contraseña requeridos' });

  const ip = getIP(req);
  const ua = req.headers['user-agent'];
  const svc = servicio || 'Desconocido';

  try {
    let solicitante = null;
    if (clientId) {
      solicitante = await findActiveSolicitante(clientId);
      if (!solicitante) return res.status(401).json({ error: 'Aplicación solicitante no autorizada' });
      const callbacks = normalizeRedirectUris(solicitante.urlOrigen, solicitante.redirectUris);
      if (servicioUrl && !isAllowedCallback(servicioUrl, callbacks)) {
        return res.status(400).json({ error: 'Callback no autorizado para esta aplicación' });
      }
    }

    const cleanDip = normalizeDip(dip);
    const registro = isDemoLogin(cleanDip, password)
      ? await ensureDemoRegistration()
      : await Registro.findOne({ dip: cleanDip });

    if (!registro) {
      await registrarLog({ dip: cleanDip, servicio: svc, servicioUrl, evento: 'error_credenciales', ip, ua, fase: 'fase1' });
      return res.status(401).json({ error: 'Credenciales incorrectas' });
    }

    if (registro.bloqueado) {
      await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: svc, servicioUrl, evento: 'cuenta_bloqueada', ip, ua, fase: 'fase1' });
      return res.status(403).json({ error: 'Cuenta bloqueada. Contacta con la Junta para el desbloqueo.', bloqueado: true });
    }

    if (!registro.activo) return res.status(403).json({ error: 'Registro inactivo' });

    // Primer acceso (registros importados sin contraseña): no puede haber una
    // contraseña "correcta" todavía. Se indica cómo fijarla en vez de contarlo
    // como intento fallido (evita bloquear a quien nunca ha entrado).
    if (!registro.passwordHash) {
      return res.status(401).json({
        error: 'Este PlacetaID aún no tiene contraseña. Fíjala al vincular tu dispositivo desde la app, o pide que la establezcan desde RSP (Administrar PlacetaID).',
        primerAcceso: true
      });
    }

    const valid = await bcrypt.compare(password, registro.passwordHash);

    if (!valid) {
      registro.intentosFallidos += 1;
      const intentos = registro.intentosFallidos;

      if (intentos >= 3) {
        registro.bloqueado = true;
        registro.ultimoBloqueo = new Date();
        await registro.save();
        await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: svc, servicioUrl, evento: 'bloqueo_activado', ip, ua, fase: 'fase1', intentoNumero: intentos });
        return res.status(403).json({ error: 'Cuenta bloqueada tras 3 intentos fallidos. Contacta con la Junta.', bloqueado: true });
      }

      await registro.save();
      await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: svc, servicioUrl, evento: 'error_credenciales', ip, ua, fase: 'fase1', intentoNumero: intentos });
      return res.status(401).json({ error: 'Credenciales incorrectas', intentosRestantes: 3 - intentos });
    }

    // El 2FA solo se EXIGE cuando está configurado Y verificado. Si la cuenta aún
    // no ha verificado su autenticador (totpVerified=false) no puede generar un
    // código: exigirlo bloquearía el acceso a pesar de tener la contraseña
    // correcta (caso real de usuarios que nunca escanearon el QR). En ese caso
    // se completa el login con la contraseña y se le animará a configurar 2FA.
    const requiere2FA = !registro.twoFactorDisabled && registro.totpVerified === true && !!registro.totpSecret;
    if (!requiere2FA) {
      const loginPayload = {
        servicio: solicitante?.nombre || svc,
        servicioUrl,
        platform: platform || solicitante?.plataforma || 'web',
        state: oauthState || null
      };
      return res.json(await completeLogin(registro, loginPayload, req, registro.twoFactorDisabled ? 'completa_sin_2fa' : 'completa_sin_2fa_no_verificado'));
    }

    // Fase 1 OK — emitir token temporal para fase 2
    const tokenFase2 = jwt.sign(
      {
        registroId: registro._id.toString(),
        dip: registro.dip,
        fase: 'fase2',
        servicio: solicitante?.nombre || svc,
        servicioUrl,
        clientId: solicitante?.apiKey || clientId || null,
        platform: platform || solicitante?.plataforma || 'web',
        state: oauthState || null,
        codeChallenge: codeChallenge || null
      },
      JWT_SECRET,
      { expiresIn: '5m' }
    );

    await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: svc, servicioUrl, evento: 'error_credenciales', ip, ua, fase: 'fase1',
      metadatos: { resultado: 'fase1_ok' } });

    // Registrar como info (no error) — reutilizamos el log con metadatos
    // Sobreescribimos con evento correcto:
    await Log.findOneAndUpdate(
      { dip: registro.dip, 'metadatos.resultado': 'fase1_ok' },
      { evento: 'intento_exitoso' },
      { sort: { timestamp: -1 } }
    );

    res.json({ ok: true, tokenFase2, mensaje: 'Fase 1 correcta. Introduce el código 2FA.' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// FASE 2: Código 2FA
app.post('/api/auth/fase2', async (req, res) => {
  const { tokenFase2, codigo2fa } = req.body;
  if (!tokenFase2 || !codigo2fa) return res.status(400).json({ error: 'Token y código 2FA requeridos' });

  const ip = getIP(req);
  const ua = req.headers['user-agent'];

  let payload;
  try {
    payload = jwt.verify(tokenFase2, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Token de fase 2 inválido o expirado. Reinicia el proceso.' });
  }

  if (payload.fase !== 'fase2') return res.status(400).json({ error: 'Token incorrecto para esta fase' });

  try {
    const registro = await Registro.findById(payload.registroId);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });

    if (registro.bloqueado) {
      return res.status(403).json({ error: 'Cuenta bloqueada. Contacta con la Junta.', bloqueado: true });
    }

    // Defensivo: si el 2FA no está verificado/configurado, no hay ningún código
    // que validar (nunca debería llegarse aquí tras el fix de fase 1).
    if (!registro.totpVerified || !registro.totpSecret) {
      return res.json(await completeLogin(registro, payload, req));
    }

    // ⚠️ BYPASS TEMPORAL DE DESARROLLO (solo si PLACETAID_DEV_BYPASS_DIP está
    // fijado y coincide con el DIP). Envía el código 'bypass'. Retirar al terminar.
    const devBypassDip = (process.env.PLACETAID_DEV_BYPASS_DIP || '').trim();
    if (devBypassDip && String(registro.dip) === devBypassDip && String(codigo2fa || '').trim().toLowerCase() === 'bypass') {
      await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: payload.servicio, servicioUrl: payload.servicioUrl, evento: 'bypass_dev_usado', ip, ua, fase: 'fase2' });
      return res.json(await completeLogin(registro, payload, req));
    }

    const verified = speakeasy.totp.verify({
      secret: registro.totpSecret,
      encoding: 'base32',
      token: codigo2fa.replace(/\s/g, ''),
      window: 1
    });

    if (!verified) {
      registro.intentosFallidos += 1;
      const intentos = registro.intentosFallidos;

      if (intentos >= 3) {
        registro.bloqueado = true;
        registro.ultimoBloqueo = new Date();
        await registro.save();
        await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: payload.servicio, servicioUrl: payload.servicioUrl, evento: 'bloqueo_activado', ip, ua, fase: 'fase2', intentoNumero: intentos });
        return res.status(403).json({ error: 'Cuenta bloqueada tras 3 intentos fallidos. Contacta con la Junta.', bloqueado: true });
      }

      await registro.save();
      await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: payload.servicio, servicioUrl: payload.servicioUrl, evento: 'error_2fa', ip, ua, fase: 'fase2', intentoNumero: intentos });
      return res.status(401).json({ error: 'Código 2FA incorrecto', intentosRestantes: 3 - intentos });
    }

    res.json(await completeLogin(registro, payload, req));

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// ── API: REGISTRO DE NUEVO USUARIO ─────────────────────────────────────────

// ── Generar token de registro para completar desde web pública ───────────
app.post('/api/registro/generar-token', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.headers['x-placetaid-client-key'];
    if (!apiKey) return res.status(401).json({ error: 'x-api-key requerido' });
    const solicitante = await Solicitante.findOne({ apiKey, activo: true });
    if (!solicitante) return res.status(401).json({ error: 'solicitante_no_autorizado' });

    const { dip } = req.body;
    if (!dip) return res.status(400).json({ error: 'dip requerido' });

    const cleanDip = normalizeDip(dip);
    const registro = await Registro.findOne({ dip: cleanDip });
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    if (registro.totpVerified) return res.status(400).json({ error: 'El 2FA ya está configurado' });

    const token = jwt.sign(
      { tipo: 'completar_registro', dip: cleanDip, registroId: registro._id.toString(), creadoPor: solicitante.nombre },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    const otpauthUrl = buildTotpUrl(cleanDip, registro.totpSecret);
    const qrCode = await QRCode.toDataURL(otpauthUrl);

    await registrarLog({ dip: cleanDip, registroId: registro._id, servicio: solicitante.nombre, evento: 'token_registro_generado', ip: getIP(req), ua: req.headers['user-agent'] });

    res.json({
      ok: true, token, qrCode, otpauthUrl, totpSecret: registro.totpSecret,
      dip: cleanDip, placeid: registro.placeid,
      nombre: `${registro.nombre} ${registro.apellidos || ''}`.trim(),
      mensaje: 'Token generado. Comparte el enlace con el ciudadano.'
    });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Error al generar token' }); }
});

// ── Info del token de registro (para vista pública) ────────────────────────
app.post('/api/registro/info-token', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token requerido' });
  try {
    const apiKey = req.headers['x-api-key'] || req.headers['x-placetaid-client-key'];
    if (!apiKey) return res.status(401).json({ error: 'x-api-key requerido' });
    const solicitante = await Solicitante.findOne({ apiKey, activo: true });
    if (!solicitante) return res.status(401).json({ error: 'solicitante_no_autorizado' });

    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Token inválido o expirado' }); }
    if (payload.tipo !== 'completar_registro') return res.status(400).json({ error: 'Token incorrecto' });

    const registro = await Registro.findById(payload.registroId);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    if (registro.totpVerified) return res.status(400).json({ error: 'El 2FA ya fue configurado' });

    const otpauthUrl = buildTotpUrl(registro.dip, registro.totpSecret);
    const qrCode = await QRCode.toDataURL(otpauthUrl);

    res.json({
      ok: true, qrCode, totpSecret: registro.totpSecret,
      dip: registro.dip, placeid: registro.placeid,
      nombre: `${registro.nombre} ${registro.apellidos || ''}`.trim()
    });
  } catch (err) { res.status(500).json({ error: 'Error interno' }); }
});

// ── Completar registro con token ──────────────────────────────────────────
app.post('/api/registro/completar-con-token', async (req, res) => {
  const { token, codigo } = req.body;
  if (!token || !codigo) return res.status(400).json({ error: 'token y codigo requeridos' });
  try {
    let payload;
    try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Token inválido o expirado.' }); }
    if (payload.tipo !== 'completar_registro') return res.status(400).json({ error: 'Token incorrecto' });

    const registro = await Registro.findById(payload.registroId);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    if (registro.totpVerified) return res.status(400).json({ error: 'El 2FA ya fue configurado' });

    const ok = speakeasy.totp.verify({ secret: registro.totpSecret, encoding: 'base32', token: codigo.replace(/\s/g, ''), window: 1 });
    if (!ok) return res.status(400).json({ error: 'Código incorrecto.' });

    registro.totpVerified = true;
    registro.activo = true;
    await registro.save();
    await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: payload.creadoPor || 'Público', evento: 'registro_completado_token', ip: getIP(req), ua: req.headers['user-agent'] });

    res.json({ ok: true, mensaje: '✅ Registro completado. Ya puedes iniciar sesión.', dip: registro.dip });
  } catch (err) { res.status(500).json({ error: 'Error al completar registro' }); }
});

app.post('/api/registro', async (req, res) => {
  try {
    const result = await createPlacetaIdRegistration(req.body, {
      servicio: 'PlacetaID',
      ip: getIP(req),
      ua: req.headers['user-agent']
    });
    res.status(201).json(result);
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : 'Error al crear el registro' });
  }
});

// Precarga independiente de PlacetaID para migrar IDs antiguos sin tocar banco/Capitalia.
app.post('/api/migraciones/pendientes', requireMigrationImport, async (req, res) => {
  try {
    const items = Array.isArray(req.body?.registros) ? req.body.registros : [req.body];
    const results = [];

    for (const item of items) {
      const dip = normalizeDip(item?.dip);
      if (!/^\d{8}[A-Z]$/.test(dip)) {
        results.push({ ok: false, dip: item?.dip, error: 'dip_invalido' });
        continue;
      }
      const placeid = normalizePlaceId(item?.placeid || item?.placeId || item?.nuevoPlaceid || item?.nuevoPlacetaId || newPlaceIdForDip(dip));
      const correo = normalizeEmail(item?.correo || item?.email);
      if (correo && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(correo)) {
        results.push({ ok: false, dip, error: 'correo_invalido' });
        continue;
      }

      const doc = await MigracionPendiente.findOneAndUpdate(
        { dip },
        {
          $set: {
            dip,
            placeid,
            placeidAnterior: normalizePlaceId(item?.placeidAnterior || item?.oldPlaceid || item?.placetaIdAnterior || ''),
            nombre: String(item?.nombre || 'Miembro').trim(),
            apellidos: String(item?.apellidos || 'GDLP').trim(),
            correo: correo || undefined,
            origen: String(item?.origen || 'migracion_gdlp').trim(),
            estado: 'pendiente'
          },
          $setOnInsert: { creadoEn: new Date() }
        },
        { upsert: true, new: true }
      );
      results.push({ ok: true, dip: doc.dip, placeid: doc.placeid, estado: doc.estado });
    }

    res.status(201).json({ ok: true, total: results.length, results });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al registrar migraciones pendientes' });
  }
});

// Consulta publica para que GDLP continue un alta normal con un DIP ya asignado.
app.get('/api/migraciones/pendientes/:dip', async (req, res) => {
  const dip = normalizeDip(req.params?.dip);
  if (!/^\d{8}[A-Z]$/.test(dip)) return res.status(400).json({ error: 'DIP invalido' });

  try {
    const pending = await MigracionPendiente.findOne({ dip, estado: 'pendiente' })
      .select('dip placeid estado');
    if (!pending) return res.status(404).json({ error: 'No hay migracion pendiente para ese DIP' });

    res.json({
      ok: true,
      dip: pending.dip,
      placeid: pending.placeid,
      estado: pending.estado
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al consultar migracion pendiente' });
  }
});

// Recuperar el QR de Authenticator de registros ya creados.
app.post('/api/registro/recuperar-authenticator', async (req, res) => {
  const dip = normalizeDip(req.body?.dip);
  const correo = normalizeEmail(req.body?.correo || req.body?.email);

  if (!dip) return res.status(400).json({ error: 'DIP requerido' });

  try {
    const pending = await MigracionPendiente.findOne({ dip, estado: 'pendiente' });
    if (pending) {
      return res.status(409).json({
        error: 'migration_requires_registration',
        dip: pending.dip,
        placeid: pending.placeid,
        mensaje: 'Completa el alta normal de GDLP con este DIP asignado para generar el QR de Authenticator.'
      });
    }

    const filter = correo ? { dip, correo } : { dip, migradoDesdePendiente: true };
    const registro = await Registro.findOne(filter);
    if (!registro) {
      await registrarLog({
        dip,
        servicio: 'PlacetaID',
        evento: 'error_credenciales',
        ip: getIP(req),
        ua: req.headers['user-agent'],
        fase: 'fase1',
        metadatos: { accion: 'recuperar_authenticator' }
      });
      return res.status(404).json({ error: correo ? 'No existe un registro con ese DIP y correo' : 'No hay migración pendiente para ese DIP' });
    }

    await registrarLog({
      dip: registro.dip,
      registroId: registro._id,
      servicio: 'PlacetaID',
      evento: 'totp_recuperado',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      fase: 'fase1'
    });

    res.json(await registrationQrResponse(registro, 'QR de Authenticator recuperado. Escanéalo de nuevo en tu aplicación 2FA.'));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al recuperar el autenticador' });
  }
});

// Alta server-to-server para portales autorizados (laplaceta.org, gdlp-web, etc.)
app.post('/api/registro/solicitante', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'] || req.headers['x-placetaid-client-key'];
    if (!apiKey) return res.status(401).json({ error: 'x-api-key requerido' });
    const solicitante = await Solicitante.findOne({ apiKey, activo: true });
    if (!solicitante) return res.status(401).json({ error: 'solicitante_no_autorizado' });

    solicitante.ultimaUsaEn = new Date();
    await solicitante.save();

    const result = await createPlacetaIdRegistration(req.body, {
      servicio: solicitante.nombre,
      servicioUrl: solicitante.urlOrigen,
      ip: getIP(req),
      ua: req.headers['user-agent'],
      metadatos: {
        solicitanteId: solicitante._id.toString(),
        plataforma: solicitante.plataforma,
        origen: req.body?.origen || 'api_solicitante'
      }
    });
    res.status(201).json({
      ...result,
      solicitante: {
        nombre: solicitante.nombre,
        plataforma: solicitante.plataforma
      }
    });
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : 'Error al crear el registro desde solicitante' });
  }
});

// Verificar TOTP tras configuración inicial
app.post('/api/registro/verificar-totp', async (req, res) => {
  const { dip, codigo } = req.body;
  try {
    const registro = await Registro.findOne({ dip: normalizeDip(dip) });
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });

    const ok = speakeasy.totp.verify({ secret: registro.totpSecret, encoding: 'base32', token: codigo?.replace(/\s/g, ''), window: 1 });
    if (!ok) return res.status(400).json({ error: 'Código incorrecto. Comprueba tu autenticador.' });

    registro.totpVerified = true;
    await registro.save();
    await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: 'PlacetaID', evento: 'totp_configurado', ip: getIP(req), ua: req.headers['user-agent'] });

    res.json({ ok: true, mensaje: 'Autenticador configurado correctamente. Ya puedes iniciar sesión.' });
  } catch (err) {
    res.status(500).json({ error: 'Error al verificar' });
  }
});

// Alta externa vía Social Login
app.post('/api/auth/social-register', async (req, res) => {
  const { socialLoginType, socialLoginId, nombre, correo } = req.body;
  if (!socialLoginType || !socialLoginId || !nombre) {
    return res.status(400).json({ error: 'socialLoginType, socialLoginId y nombre son requeridos' });
  }
  try {
    const existe = await Registro.findOne({ socialLoginType, socialLoginId });
    if (existe) {
      return res.status(409).json({ error: 'Esta cuenta social ya está registrada' });
    }
    const supportNumber = await generateUniqueSupportNumber();
    const placeid = `PLID-${supportNumber}`;
    const registro = await Registro.create({
      supportNumber,
      placeid,
      nombre,
      correo: correo ? normalizeEmail(correo) : undefined,
      socialLoginType,
      socialLoginId,
      rol: 'visitante'
    });
    await registrarLog({
      dip: registro.supportNumber,
      registroId: registro._id,
      servicio: 'PlacetaID Social Register',
      evento: 'registro_creado',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      metadatos: { socialLoginType, socialLoginId }
    });
    res.status(201).json({
      ok: true,
      supportNumber: registro.supportNumber,
      placeid: registro.placeid,
      nombre: registro.nombre,
      rol: registro.rol,
      mensaje: 'Registro social completado'
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al registrar usuario social' });
  }
});

// Login vía Social Login
app.post('/api/auth/social-login', async (req, res) => {
  const { supportNumber, socialLoginType, socialLoginId, servicio, servicioUrl, platform, state: oauthState } = req.body;
  if (!supportNumber || !socialLoginType || !socialLoginId) {
    return res.status(400).json({ error: 'supportNumber, socialLoginType y socialLoginId son requeridos' });
  }
  try {
    const registro = await Registro.findOne({ supportNumber });
    if (!registro) {
      return res.status(401).json({ error: 'Número de soporte no encontrado' });
    }
    if (registro.socialLoginType !== socialLoginType || registro.socialLoginId !== socialLoginId) {
      return res.status(401).json({ error: 'La cuenta social no coincide con el número de soporte' });
    }
    if (registro.bloqueado) {
      if (registro.bannedUntil && new Date(registro.bannedUntil) < new Date()) {
        registro.bloqueado = false;
        registro.banned = false;
        registro.bannedUntil = null;
        await registro.save();
      } else {
        return res.status(403).json({ error: 'Cuenta bloqueada/baneada', bloqueado: true });
      }
    }
    const loginPayload = {
      servicio: servicio || 'Desconocido',
      servicioUrl,
      platform: platform || 'web',
      state: oauthState || null
    };
    res.json(await completeLogin(registro, loginPayload, req));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al iniciar sesión' });
  }
});

// Vincular DIP en el futuro
app.post('/api/registro/link-dip', async (req, res) => {
  const { supportNumber, dip, password, email } = req.body;
  if (!supportNumber || !dip || !password) {
    return res.status(400).json({ error: 'supportNumber, dip y contraseña son requeridos' });
  }
  try {
    const registro = await Registro.findOne({ supportNumber });
    if (!registro) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (registro.dip) return res.status(400).json({ error: 'Este usuario ya tiene un DIP vinculado' });

    const cleanDip = normalizeDip(dip);
    const dipExiste = await Registro.exists({ dip: cleanDip });
    if (dipExiste) return res.status(409).json({ error: 'El DIP ya está registrado en otra cuenta' });

    validateDipForName(cleanDip, registro.nombre);

    const passwordHash = await bcrypt.hash(password, 12);
    const totp = speakeasy.generateSecret({ name: `PlacetaID:${cleanDip}`, issuer: 'Grupo de La Placeta', length: 20 });

    registro.dip = cleanDip;
    registro.passwordHash = passwordHash;
    registro.totpSecret = totp.base32;
    registro.totpVerified = false;
    registro.twoFactorDisabled = false;
    if (email) registro.correo = normalizeEmail(email);

    await registro.save();

    await registrarLog({
      dip: registro.dip,
      registroId: registro._id,
      servicio: 'PlacetaID Link DIP',
      evento: 'totp_configurado',
      ip: getIP(req),
      ua: req.headers['user-agent']
    });

    const otpauthUrl = totp.otpauth_url || buildTotpUrl(registro.dip, totp.base32);
    const qrCode = await QRCode.toDataURL(otpauthUrl);

    res.json({
      ok: true,
      dip: registro.dip,
      totpSecret: totp.base32,
      qrCode,
      otpauthUrl,
      mensaje: 'DIP vinculado correctamente. Escanea el código QR de Authenticator.'
    });
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.message || 'Error al vincular DIP' });
  }
});

// Banear indefinidamente o hasta x fecha
app.post('/api/admin/ban', verifyAdminApiKey, requireAdmin, async (req, res) => {
  const { dip, supportNumber, banned, bannedUntil } = req.body;
  try {
    const query = dip ? { dip: normalizeDip(dip) } : { supportNumber };
    const registro = await Registro.findOne(query);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });

    registro.bloqueado = Boolean(banned);
    registro.banned = Boolean(banned);
    registro.bannedUntil = bannedUntil ? new Date(bannedUntil) : null;
    await registro.save();

    await registrarLog({
      dip: registro.dip || registro.supportNumber,
      registroId: registro._id,
      servicio: 'PlacetaID Admin',
      evento: banned ? 'bloqueo_activado' : 'desbloqueado',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      metadatos: { banStatus: banned, bannedUntil, bannedPor: req.user.dip }
    });

    res.json({
      ok: true,
      mensaje: `Registro ${registro.dip || registro.supportNumber} actualizado (banned: ${banned})`
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al procesar sanción / ban' });
  }
});

// ── Restablecer contraseña (RSP / Admin) ─────────────────────────────────────
// Lo usa la pantalla «Administrar PlacetaID» del RSP (Fijar contraseña):
// el RSP reenvía { dip, passwordNueva } con X-API-Key. Aquí se aplica el
// hash bcrypt y se guarda en el MISMO registro que valida el login
// (/api/auth/fase1). Se desbloquea la cuenta, se resetean intentos y se
// invalidan tokens anteriores (tokenVersion++).
app.post('/api/admin/cambiar-password', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const dip = normalizeDip(req.body?.dip || '');
    const supportNumber = String(req.body?.supportNumber || '').trim();
    // Acepta passwordNueva (RSP) y también password/nuevaPassword por robustez.
    const password = String(req.body?.passwordNueva || req.body?.password || req.body?.nuevaPassword || '');

    if (!dip && !supportNumber) return res.status(400).json({ error: 'dip_o_supportNumber_requerido' });
    if (password.length < 8 || !/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
      return res.status(400).json({ error: 'La contraseña debe tener al menos 8 caracteres, letras y números' });
    }

    const query = supportNumber && !dip ? { supportNumber } : { dip };
    const registro = await Registro.findOne(query);
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    if (!registro.activo) return res.status(403).json({ error: 'Registro inactivo' });

    const passwordHash = await bcrypt.hash(password, 12);
    registro.passwordHash = passwordHash;
    registro.intentosFallidos = 0;
    registro.bloqueado = false;
    registro.ultimoBloqueo = null;
    registro.passwordChangedAt = new Date();
    // La contraseña temporal cifrada del alta ya no es necesaria.
    if (registro.passwordDefaultCifrado) registro.passwordDefaultCifrado = undefined;
    registro.tokenVersion = (registro.tokenVersion || 0) + 1;
    await registro.save();

    await registrarLog({
      dip: registro.dip || registro.supportNumber,
      registroId: registro._id,
      servicio: 'PlacetaID Admin',
      evento: 'password_reset',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      metadatos: { cambiadaPor: req.user?.dip || 'api-key' }
    });

    res.json({ ok: true, dip: registro.dip || null, mensaje: 'Contraseña restablecida correctamente' });
  } catch (err) {
    console.error(err);
    res.status(err.statusCode || 500).json({ error: err.message || 'Error al cambiar la contraseña' });
  }
});

// ── API: PANEL JUNTA (ADMIN) ──────────────────────────────────────────────────

// Login de admin (misma pasarela pero devuelve token admin)
// El admin usa la pasarela normal.

// Listar registros
app.get('/api/admin/registros', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const registros = await Registro.find({}, '-passwordHash -totpSecret').sort({ creadoEn: -1 });
    const result = registros.map(r => ({
      ...r.toJSON(),
      edad: r.edad
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener registros' });
  }
});

// Desbloquear cuenta
app.post('/api/admin/desbloquear/:dip', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const registro = await Registro.findOne({ dip: normalizeDip(req.params.dip) });
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });

    registro.bloqueado = false;
    registro.intentosFallidos = 0;
    await registro.save();

    await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: 'PlacetaID Admin', evento: 'desbloqueado', ip: getIP(req), ua: req.headers['user-agent'], metadatos: { desbloqueadoPor: req.user.dip } });

    res.json({ ok: true, mensaje: `Registro ${registro.dip} desbloqueado correctamente` });
  } catch (err) {
    res.status(500).json({ error: 'Error al desbloquear' });
  }
});

// Activar/desactivar registro
app.post('/api/admin/toggle/:dip', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const registro = await Registro.findOne({ dip: normalizeDip(req.params.dip) });
    if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
    registro.activo = !registro.activo;
    await registro.save();
    res.json({ ok: true, activo: registro.activo });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Logs con filtros
app.get('/api/admin/logs', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const { dip, evento, limit = 100, page = 1 } = req.query;
    const filter = {};
    if (dip) filter.dip = normalizeDip(dip);
    if (evento) filter.evento = evento;

    const logs = await Log.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit))
      .skip((parseInt(page) - 1) * parseInt(limit));

    const total = await Log.countDocuments(filter);
    res.json({ logs, total, page: parseInt(page), limit: parseInt(limit) });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener logs' });
  }
});

// Stats del dashboard
app.get('/api/admin/stats', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const [total, bloqueados, activos, logsHoy] = await Promise.all([
      Registro.countDocuments(),
      Registro.countDocuments({ bloqueado: true }),
      Registro.countDocuments({ activo: true, bloqueado: false }),
      Log.countDocuments({ timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } })
    ]);
    const [solicitantes, solicitantesActivos, registrosHoy] = await Promise.all([
      Solicitante.countDocuments(),
      Solicitante.countDocuments({ activo: true }),
      Registro.countDocuments({ creadoEn: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } })
    ]);
    const exitososHoy = await Log.countDocuments({ evento: 'intento_exitoso', timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    const erroresHoy = await Log.countDocuments({ evento: { $in: ['error_credenciales', 'error_2fa'] }, timestamp: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
    res.json({ total, bloqueados, activos, logsHoy, exitososHoy, erroresHoy, solicitantes, solicitantesActivos, registrosHoy });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener estadísticas' });
  }
});

// ── API: GESTIÓN DE SOLICITANTES (ADMIN) ──────────────────────────────────────
// Crear solicitante
app.post('/api/admin/solicitantes', verifyAdminApiKey, requireAdmin, async (req, res) => {
  const {
    nombre,
    descripcion,
    urlOrigen,
    redirectUris,
    plataforma = 'web',
    appScheme,
    packageName,
    bundleId,
    deepLinkHost,
    pkceRequired = true,
    permitirWebFallback = true,
    logo = '',
    bgColor = ''
  } = req.body;
  const callbacks = normalizeRedirectUris(urlOrigen, redirectUris);
  if (!nombre || callbacks.length === 0) return res.status(400).json({ error: 'Nombre y al menos un callback son requeridos' });

  try {
    const apiKey = require('crypto').randomBytes(16).toString('hex');
    const solicitante = await Solicitante.create({
      nombre,
      descripcion,
      plataforma,
      urlOrigen: callbacks[0],
      redirectUris: callbacks,
      appScheme,
      packageName,
      bundleId,
      deepLinkHost,
      pkceRequired: Boolean(pkceRequired),
      permitirWebFallback: Boolean(permitirWebFallback),
      logo,
      bgColor,
      apiKey,
      creadoPor: req.user.registroId
    });
    res.status(201).json({ ok: true, solicitante, apiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Listar solicitantes
app.get('/api/admin/solicitantes', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const solicitantes = await Solicitante.find({}, '-apiKey').sort({ creadoEn: -1 });
    res.json(solicitantes);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener solicitantes' });
  }
});

// Obtener solicitante con apiKey (para admin)
app.get('/api/admin/solicitantes/:id', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const solicitante = await Solicitante.findById(req.params.id);
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    res.json(solicitante); // Incluye apiKey
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Eliminar solicitante
app.delete('/api/admin/solicitantes/:id', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const solicitante = await Solicitante.findByIdAndDelete(req.params.id);
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    invalidateSolicitanteCache(solicitante.apiKey);
    res.json({ ok: true, mensaje: 'Solicitante eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// ── Subir logo de solicitante (base64, max 256KB) ──
app.post('/api/admin/solicitantes/upload-logo', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const { dataUrl } = req.body;
    if (!dataUrl || typeof dataUrl !== 'string') return res.status(400).json({ error: 'dataUrl requerido' });
    if (!dataUrl.startsWith('data:image/')) return res.status(400).json({ error: 'Solo se permiten imágenes en data URL' });
    // Limitar tamaño (~256KB en base64)
    if (dataUrl.length > 350000) return res.status(400).json({ error: 'Logo demasiado grande (máx 256KB)' });
    res.json({ ok: true, logo: dataUrl });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Actualizar branding de solicitante (logo + bgColor) ──
app.patch('/api/admin/solicitantes/:id/branding', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const { logo, bgColor } = req.body;
    const update = {};
    if (logo !== undefined) update.logo = logo;
    if (bgColor !== undefined) update.bgColor = bgColor;
    if (!Object.keys(update).length) return res.status(400).json({ error: 'Nada que actualizar' });

    const solicitante = await Solicitante.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    invalidateSolicitanteCache(solicitante.apiKey);
    res.json({ ok: true, solicitante });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Actualizar solicitante completo (PUT) ────────────────────────────────────
app.put('/api/admin/solicitantes/:id', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const allowed = ['nombre','descripcion','plataforma','urlOrigen','redirectUris','appScheme','packageName','bundleId','deepLinkHost','pkceRequired','permitirWebFallback','logo','bgColor','activo'];
    const update = {};
    for (const field of allowed) {
      if (req.body[field] !== undefined) update[field] = req.body[field];
    }
    if (!Object.keys(update).length) return res.status(400).json({ error: 'Nada que actualizar' });

    // Si se actualiza urlOrigen y no redirectUris, sincronizar
    if (update.urlOrigen && !req.body.redirectUris) {
      update.redirectUris = [update.urlOrigen];
    }

    const solicitante = await Solicitante.findByIdAndUpdate(req.params.id, update, { new: true });
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    invalidateSolicitanteCache(solicitante.apiKey);
    res.json({ ok: true, solicitante });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Obtener info del solicitante en producción (validar por apiKey)
app.get('/api/solicitante/info', async (req, res) => {
  const key = req.headers['x-api-key'];
  if (!key) return res.status(401).json({ error: 'API Key requerida' });

  try {
    const solicitante = await findActiveSolicitante(key);
    if (!solicitante) return res.status(401).json({ error: 'API Key inválida o inactiva' });
    
    if (typeof solicitante.save === 'function') {
      solicitante.ultimaUsaEn = new Date();
      await solicitante.save();
    }
    
    res.json({
      nombre: solicitante.nombre,
      descripcion: solicitante.descripcion,
      plataforma: solicitante.plataforma,
      urlOrigen: solicitante.urlOrigen || (Array.isArray(solicitante.redirectUris) && solicitante.redirectUris[0]) || null,
      redirectUris: normalizeRedirectUris(solicitante.urlOrigen, solicitante.redirectUris),
      appScheme: solicitante.appScheme,
      packageName: solicitante.packageName,
      bundleId: solicitante.bundleId,
      deepLinkHost: solicitante.deepLinkHost,
      pkceRequired: solicitante.pkceRequired,
      permitirWebFallback: solicitante.permitirWebFallback,
      logo: solicitante.logo || '',
      bgColor: solicitante.bgColor || ''
    });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Obtener instrucciones de implementación (admin)
app.get('/api/admin/solicitantes/:id/instrucciones', verifyAdminApiKey, requireAdmin, async (req, res) => {
  try {
    const solicitante = await Solicitante.findById(req.params.id);
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });

    const baseUrl = process.env.BASE_URL || 'https://id.laplaceta.org';
    const callbacks = normalizeRedirectUris(solicitante.urlOrigen, solicitante.redirectUris);
    const callbackPrincipal = callbacks[0] || solicitante.urlOrigen;
    const loginUrl = `${baseUrl}/?client_id=${solicitante.apiKey}&redirect_uri=${encodeURIComponent(callbackPrincipal)}&platform=${solicitante.plataforma}&state=estado-seguro-aleatorio`;
    const instrucciones = {
      nombre: solicitante.nombre,
      apiKey: solicitante.apiKey,
      urlOrigen: solicitante.urlOrigen,
      plataforma: solicitante.plataforma,
      redirectUris: callbacks,
      basePath: baseUrl,
      html: `
<!-- PLID26 / PlacetaID Integration -->
<button id="placetaidLoginBtn" style="padding:10px 20px;background:#3F00D8;color:white;border:none;border-radius:8px;cursor:pointer;font-weight:700;">
  Iniciar sesión con PlacetaID
</button>

<script>
const PLACETAID_CONFIG = {
  baseUrl: '${baseUrl}',
  clientId: '${solicitante.apiKey}',
  callbackUrl: '${callbackPrincipal}',
  platform: '${solicitante.plataforma}',
  serviceName: '${solicitante.nombre}'
};

document.getElementById('placetaidLoginBtn').addEventListener('click', () => {
  const url = new URL(PLACETAID_CONFIG.baseUrl + '/');
  url.searchParams.set('client_id', PLACETAID_CONFIG.clientId);
  url.searchParams.set('redirect_uri', PLACETAID_CONFIG.callbackUrl);
  url.searchParams.set('platform', PLACETAID_CONFIG.platform);
  url.searchParams.set('state', crypto.randomUUID());
  window.location.href = url.toString();
});
</script>`,
      implementacion: `
## PLID26 listo para ${platformLabel(solicitante.plataforma)}

### Callbacks autorizados
${callbacks.map(uri => `- ${uri}`).join('\n')}

### Login web
Redirige al usuario a:
${loginUrl}

### Login Android / apps nativas
Registra un callback deep link autorizado, por ejemplo:
${solicitante.appScheme || 'placetaid-demo'}://${solicitante.deepLinkHost || 'auth/callback'}

Abre PLID26 con los mismos parámetros:
\`client_id\`, \`redirect_uri\`, \`platform=android\` y \`state\`.

Si el dispositivo tiene la app instalada, el callback puede volver por deep link. Si no, usa el fallback web autorizado.

### Login iOS
Usa Universal Link o esquema propio registrado como redirect URI. El flujo devuelve los mismos parámetros que web.

### API de altas PlacetaID
Para crear una identidad desde laplaceta.org, GDLP u otro backend autorizado:

\`\`\`javascript
const res = await fetch('${baseUrl}/api/registro/solicitante', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'X-API-Key': '${solicitante.apiKey}'
  },
  body: JSON.stringify({
    nombre: 'Nombre',
    apellidos: 'Apellidos',
    fechaNacimiento: '1990-01-31',
    password: 'clave-temporal-segura',
    origen: '${solicitante.plataforma || 'web'}'
  })
});

const alta = await res.json();
console.log('PlacetaID creado:', alta.dip);
\`\`\`

El campo \`dip\` es opcional. Si no se envia, PLID26 generara uno automaticamente.

### 3. Capturar el callback
\`\`\`javascript
const params = new URLSearchParams(window.location.search);
const token = params.get('placetaid_token') || params.get('token');
const user = params.get('user');
const state = params.get('state');

if (token && user) {
  localStorage.setItem('placetaidToken', token);
  localStorage.setItem('placetaidUser', user);
  const usuario = JSON.parse(decodeURIComponent(user));
  console.log('Usuario autenticado:', usuario);
}
\`\`\`

### 4. Validación
Desde backend puedes validar la aplicación registrada:

\`\`\`javascript
fetch('${baseUrl}/api/solicitante/info', {
  headers: { 'X-API-Key': '${solicitante.apiKey}' }
})
.then(r => r.json())
.then(data => console.log(data));
\`\`\`

### 5. Notas
- El token expira en 1 hora.
- \`redirect_uri\` debe coincidir exactamente con un callback autorizado.
- \`state\` debe generarse por operación y verificarse al volver.
- La API Key identifica el cliente. No la uses para autorizar operaciones sensibles desde frontend.
- Compatible con web, apps Android/iOS, escritorio y backend mediante callbacks registrados.
`
    };

    res.json(instrucciones);
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// ── SEED ADMIN (solo en desarrollo) ──────────────────────────────────────────
app.post('/api/setup/seed-demo', async (req, res) => {
  try {
    console.log('🔧 POST /api/setup/seed-demo - Chequeando DB connection...');
    await ensureDemoRegistration();

    console.log('✓ Demo creado/actualizado exitosamente');
    res.json({ ok: true, dip: DEMO_USER.dip, password: DEMO_USER.password, requiere2fa: false, mensaje: 'Usuario demo creado/actualizado para desarrollo. No requiere 2FA.' });
  } catch (err) {
    console.error('❌ Error en seed-demo:', err.message, err.code);
    res.status(500).json({ error: err.message, code: err.code });
  }
});

app.post('/api/setup/seed-admin', async (req, res) => {
  try {
    console.log('🔧 POST /api/setup/seed-admin - Chequeando DB connection...');
    const adminDip = '00000000A';
    
    const existe = await Registro.findOne({ dip: adminDip });
    if (existe) {
      console.log('✓ Admin ya existe');
      return res.json({ ok: false, mensaje: `El admin ya existe. DIP: ${adminDip}` });
    }

    const passwordHash = await bcrypt.hash('Admin1234!', 12);
    const totp = speakeasy.generateSecret({ name: `PlacetaID:${adminDip}`, issuer: 'Grupo de La Placeta', length: 20 });
    const qrUrl = await QRCode.toDataURL(totp.otpauth_url);

    await Registro.create({
      dip: adminDip, nombre: 'Administrador', apellidos: 'del Sistema',
      fechaNacimiento: new Date('1990-01-01'), rol: 'administrador',
      passwordHash, totpSecret: totp.base32, totpVerified: true
    });

    console.log('✓ Admin creado exitosamente');
    res.json({ ok: true, dip: adminDip, password: 'Admin1234!', totpSecret: totp.base32, qrCode: qrUrl, mensaje: '⚠️ Admin creado. Guarda el secreto TOTP y elimina este endpoint en producción.' });
  } catch (err) {
    console.error('❌ Error en seed-admin:', err.message, err.code);
    res.status(500).json({ error: err.message, code: err.code });
  }
});

// ── API: PLACETAID MÓVIL ─────────────────────────────────────────────────────

// Registrar dispositivo móvil asociado a un PlacetaID
// Registrar dispositivo (móvil o PC)
app.post('/api/mobil/register', async (req, res) => {
  try {
    const { dip, password, deviceId, deviceToken, deviceName, platform } = req.body;
    if (!dip || !password || !(deviceId || deviceToken)) return res.status(400).json({ error: 'DIP, contraseña y deviceId requeridos' });
    const devId = deviceId || deviceToken;

    const cleanDip = normalizeDip(dip);
    // El usuario demo (11111111D) siempre debe poder vincularse: se auto-registra
    // y auto-repara (resetea contraseña demo, desbloquea y desactiva 2FA).
    const registro = isDemoLogin(cleanDip, password)
      ? await ensureDemoRegistration()
      : await Registro.findOne({ dip: cleanDip });
    if (!registro) {
      return res.status(404).json({ error: 'PlacetaID no encontrado para este DIP. Solicita el alta en la Junta o revisa el DIP.' });
    }
    if (registro.bloqueado || !registro.activo) return res.status(403).json({ error: 'PlacetaID bloqueado o inactivo' });

    // ── PRIMER ACCESO (gente que nunca ha entrado) ─────────────────────────
    // Hay registros importados/creados por el RSP SIN contraseña aún. Para esas
    // personas, la contraseña que escriben en este paso de "vincular dispositivo"
    // es la que eligen/confirman como suya: se guarda cifrada y pueden entrar.
    if (!registro.passwordHash) {
      const passwordHash = await bcrypt.hash(password, 12);
      registro.passwordHash = passwordHash;
      registro.passwordChangedAt = new Date();
      registro.bloqueado = false;
      registro.intentosFallidos = 0;
      await registro.save();
      try { await registrarLog({
        dip: cleanDip, registroId: registro._id,
        servicio: 'PlacetaID', evento: 'primer_acceso_password_creado',
        ip: getIP(req), ua: req.headers['user-agent'], fase: 'registro_dispositivo',
        metadatos: { accion: 'registro_dispositivo', resultado: 'primer_acceso' }
      }); } catch (_) {}
    }

    // Verify password
    const passwordValid = await bcrypt.compare(password, registro.passwordHash);
    if (!passwordValid) {
      try { await registrarLog({
        dip: cleanDip, registroId: registro._id,
        servicio: 'PlacetaID', evento: 'error_credenciales',
        ip: getIP(req), ua: req.headers['user-agent'], fase: 'registro_dispositivo',
        metadatos: { accion: 'registro_dispositivo', resultado: 'password_incorrecta' }
      }); } catch (_) {}
      return res.status(401).json({ error: 'Contraseña incorrecta. Si nunca la has usado, fíjala desde RSP (Administrar PlacetaID → Fijar contraseña) o pide que la restablezcan.' });
    }

    const tipo = platform === 'pc' || platform === 'windows' || platform === 'mac' || platform === 'linux' ? 'pc' : 'movil';

    // ── Vincular dispositivo (móvil o PC) ─────────────────────────────────
    // El mismo dispositivo es idempotente (se actualiza, nunca 409 por repetir).
    const mismo = await MobileDevice.findOne({ dip: cleanDip, deviceId: devId });
    if (mismo) {
      // OJO: la colección tiene un índice UNIQUE legacy sobre deviceToken; se
      // guarda siempre un valor real (nunca null) para no chocar con él.
      mismo.deviceToken = devId;
      mismo.deviceName = deviceName || mismo.deviceName || (tipo === 'pc' ? 'PC' : 'Dispositivo móvil');
      mismo.platform = platform || mismo.platform || (tipo === 'pc' ? 'windows' : 'android');
      mismo.tipo = tipo;
      mismo.activo = true;
      mismo.ultimoAcceso = new Date();
      await mismo.save();
      return res.json({ ok: true, mensaje: `${tipo === 'pc' ? 'PC' : 'Dispositivo'} actualizado` });
    }

    if (tipo === 'movil') {
      // Un ciudadano usa UN móvil. Si ya se verificó su contraseña, vincular
      // un móvil nuevo (reinstalación, cambio de teléfono o recuperación)
      // SUSTITUYE cualquier móvil anterior de este DIP: nunca un 409.
      await MobileDevice.deleteMany({ dip: cleanDip, tipo: 'movil' });
      await MobileDevice.create({
        dip: cleanDip,
        deviceId: devId,
        deviceToken: devId,
        deviceName: deviceName || 'Dispositivo móvil',
        platform: platform || 'android',
        tipo,
        activo: true
      });
      await registrarLog({
        dip: cleanDip, registroId: registro._id,
        servicio: 'PlacetaID', evento: 'intento_exitoso',
        ip: getIP(req), ua: req.headers['user-agent'], fase: 'registro_dispositivo',
        metadatos: { accion: 'registro_dispositivo', resultado: 'nuevo_movil_reemplaza', tipo }
      });
      return res.json({ ok: true, mensaje: 'Móvil vinculado correctamente' });
    }

    // PC: máximo 3 por DIP (el mismo deviceId ya se actualizó arriba).
    const pcCount = await MobileDevice.countDocuments({ dip: cleanDip, tipo: 'pc', activo: true });
    if (pcCount >= 3) {
      return res.status(409).json({ error: 'Límite de 3 PCs alcanzado. Desvincula uno primero.' });
    }
    await MobileDevice.create({
      dip: cleanDip,
      deviceId: devId,
      deviceToken: devId,
      deviceName: deviceName || 'PC',
      platform: platform || 'windows',
      tipo,
      activo: true
    });
    await registrarLog({
      dip: cleanDip, registroId: registro._id,
      servicio: 'PlacetaID', evento: 'intento_exitoso',
      ip: getIP(req), ua: req.headers['user-agent'], fase: 'registro_dispositivo',
      metadatos: { accion: 'registro_dispositivo', resultado: 'nuevo_pc', tipo }
    });
    res.json({ ok: true, mensaje: 'PC vinculado correctamente' });
  } catch (err) {
    console.error('Error register device:', err);
    res.status(500).json({ error: 'Error al registrar dispositivo' });
  }
});

// Desvincular dispositivo
app.post('/api/mobil/unregister', async (req, res) => {
  try {
    const { dip, deviceId } = req.body;
    if (!dip && !deviceId) return res.status(400).json({ error: 'DIP o deviceId requerido' });

    let deleted;
    if (deviceId) {
      // Buscar por deviceId o _id (para compatibilidad con docs antiguos)
      deleted = await MobileDevice.findOneAndDelete({
        $or: [{ deviceId }, { _id: deviceId.match(/^[0-9a-f]{24}$/i) ? deviceId : undefined }]
      });
      // Si no se encontró, intentar por _id directamente
      if (!deleted && deviceId.match(/^[0-9a-f]{24}$/i)) {
        deleted = await MobileDevice.findByIdAndDelete(deviceId);
      }
    }
    if (!deleted && dip) {
      deleted = await MobileDevice.findOneAndDelete({ dip: normalizeDip(dip) });
    }
    if (!deleted) return res.status(404).json({ error: 'No hay dispositivo registrado' });

    console.log(`💻 Dispositivo desvinculado: ${deleted.deviceName || 'unknown'} (${deleted.dip})`);
    res.json({ ok: true, mensaje: 'Dispositivo desvinculado' });
  } catch (err) {
    console.error('Error unregister:', err);
    res.status(500).json({ error: 'Error al desvincular dispositivo' });
  }
});

// Listar dispositivos de un DIP
app.get('/api/mobil/devices/:dip', async (req, res) => {
  try {
    const devices = await MobileDevice.find({ dip: normalizeDip(req.params.dip), activo: true })
      .select('deviceId deviceName platform tipo ultimoAcceso registradoEn')
      .sort({ registradoEn: -1 });
    // Para documentos antiguos sin deviceId, usar _id como fallback
    const result = devices.map(d => ({
      deviceId: d.deviceId || d._id.toString(),
      deviceName: d.deviceName || 'Dispositivo',
      platform: d.platform || 'desconocida',
      tipo: d.tipo || 'movil',
      ultimoAcceso: d.ultimoAcceso,
      registradoEn: d.registradoEn
    }));
    res.json({ ok: true, devices: result });
  } catch (err) {
    console.error('Error listar dispositivos:', err);
    res.status(500).json({ error: 'Error al listar dispositivos' });
  }
});

// Generar código de solicitud de autenticación (desde web)
app.post('/api/mobil/request', async (req, res) => {
  try {
    const { dip, servicio, servicioUrl, plataforma } = req.body;
    if (!dip || !servicio) return res.status(400).json({ error: 'DIP y servicio requeridos' });

    const cleanDip = normalizeDip(dip);

    // Generate short code
    const codigo = crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 4);

    const authReq = await AuthRequest.create({
      codigo,
      dip: cleanDip,
      servicio,
      servicioUrl: servicioUrl || null,
      plataforma: plataforma || 'web',
      estado: 'pending',
      expiraEn: new Date(Date.now() + 5 * 60 * 1000) // 5 min
    });

    // Registrar en auditoría
    const registro = await Registro.findOne({ dip: cleanDip });
    await registrarLog({
      dip: cleanDip,
      registroId: registro?._id,
      servicio,
      servicioUrl: servicioUrl || undefined,
      evento: 'intento_exitoso',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      fase: 'móvil',
      metadatos: { tipo: 'placetaid_movil_solicitud', codigo, requestId: authReq._id.toString(), plataforma: plataforma || 'web' }
    });

    console.log(`📱 Solicitud ${codigo} creada para ${cleanDip} desde ${servicio}`);

    res.json({
      ok: true,
      codigo,
      requestId: authReq._id.toString(),
      mensaje: `Código ${codigo} generado. Revisa tu app PlacetaID Móvil.`
    });
  } catch (err) {
    console.error('Error create request:', err);
    res.status(500).json({ error: 'Error al crear solicitud' });
  }
});

// Obtener solicitudes pendientes por DIP
app.get('/api/mobil/pending', async (req, res) => {
  try {
    const dip = req.query.dip;
    if (!dip) return res.status(400).json({ error: 'dip requerido' });

    const cleanDip = normalizeDip(dip);

    const requests = await AuthRequest.find({
      dip: cleanDip,
      estado: 'pending',
      expiraEn: { $gt: new Date() }
    }).sort({ creadoEn: -1 }).limit(20);

    res.json({ ok: true, requests });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener solicitudes' });
  }
});

// Autorizar o denegar una solicitud
app.post('/api/mobil/authorize', async (req, res) => {
  try {
    const { requestId, dip, authorized } = req.body;
    if (!requestId || !dip) return res.status(400).json({ error: 'requestId y dip requeridos' });

    const cleanDip = normalizeDip(dip);

    const authReq = await AuthRequest.findById(requestId);
    if (!authReq) return res.status(404).json({ error: 'Solicitud no encontrada' });
    if (authReq.dip !== cleanDip) return res.status(403).json({ error: 'Esta solicitud no corresponde a este DIP' });
    if (authReq.estado !== 'pending') return res.status(400).json({ error: `La solicitud ya fue ${authReq.estado}` });
    if (authReq.expiraEn < new Date()) {
      authReq.estado = 'expired';
      await authReq.save();
      return res.status(400).json({ error: 'La solicitud ha expirado' });
    }

    authReq.estado = authorized ? 'authorized' : 'denied';
    authReq.autorizadoEn = new Date();
    await authReq.save();

    // Detectar origen (mobile app vs desktop app)
    const ua = req.headers['user-agent'] || '';
    const origenApp = ua.includes('Electron') || ua.includes('placetaid-desktop') ? 'desktop' : 'movil';

    // Log the event
    await registrarLog({
      dip: cleanDip,
      registroId: (await Registro.findOne({ dip: cleanDip }))?._id,
      servicio: authReq.servicio,
      servicioUrl: authReq.servicioUrl,
      evento: authorized ? 'intento_exitoso' : 'error_credenciales',
      ip: getIP(req),
      ua: req.headers['user-agent'],
      fase: 'móvil',
      metadatos: { tipo: `placetaid_${origenApp}`, codigo: authReq.codigo, requestId: authReq._id.toString(), origen: origenApp }
    });

    console.log(`📱 Solicitud ${authReq.codigo} ${authorized ? 'AUTORIZADA' : 'DENEGADA'} para ${cleanDip} (${origenApp})`);

    res.json({ ok: true, estado: authReq.estado, mensaje: authorized ? 'Solicitud autorizada' : 'Solicitud denegada' });
  } catch (err) {
    console.error('Error authorize:', err);
    res.status(500).json({ error: 'Error al procesar solicitud' });
  }
});

// Verificar estado de un PlacetaID (para la app móvil)
app.get('/api/mobil/status/:dip', async (req, res) => {
  try {
    const dip = normalizeDip(req.params.dip);
    const registro = await Registro.findOne({ dip }).select('-passwordHash -totpSecret');

    if (!registro) return res.status(404).json({ error: 'PlacetaID no encontrado' });

    res.json({
      ok: true,
      activo: registro.activo && !registro.bloqueado,
      bloqueado: registro.bloqueado || registro.banned || false,
      registro: publicRegistroData(registro)
    });
  } catch (err) {
    res.status(500).json({ error: 'Error al consultar estado' });
  }
});

// Poll: comprobar si una solicitud fue autorizada (para la web)
app.get('/api/mobil/poll/:requestId', async (req, res) => {
  try {
    const authReq = await AuthRequest.findById(req.params.requestId);
    if (!authReq) return res.status(404).json({ error: 'Solicitud no encontrada' });

    if (authReq.estado === 'authorized') {
      // Complete login for this user
      const registro = await Registro.findOne({ dip: authReq.dip });
      if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });

      const payload = {
        servicio: authReq.servicio,
        servicioUrl: authReq.servicioUrl,
        platform: authReq.plataforma || 'web',
        state: null
      };

      const loginResult = await completeLogin(registro, payload, req, 'móvil');
      return res.json({ ok: true, autorizado: true, ...loginResult });
    }

    if (authReq.estado === 'denied') {
      return res.json({ ok: true, autorizado: false, estado: 'denied', mensaje: 'Solicitud denegada' });
    }

    if (authReq.estado === 'expired' || authReq.expiraEn < new Date()) {
      if (authReq.estado === 'pending') {
        authReq.estado = 'expired';
        await authReq.save();
      }
      return res.json({ ok: true, autorizado: false, estado: 'expired', mensaje: 'La solicitud ha expirado' });
    }

    // Still pending
    res.json({ ok: true, autorizado: false, estado: 'pending' });
  } catch (err) {
    // Un identificador inexistente no es un fallo interno del servidor.
    // La app cliente puede tratarlo como solicitud caducada/no disponible.
    if (err?.name === 'CastError' || err?.name === 'BSONTypeError') {
      return res.status(404).json({ error: 'Solicitud no encontrada' });
    }
    res.status(500).json({ error: 'Error al consultar solicitud' });
  }
});

// Obtener historial de acceso (para la app móvil)
app.get('/api/mobil/history/:dip', async (req, res) => {
  try {
    const dip = normalizeDip(req.params.dip);
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);

    const logs = await Log.find({ dip })
      .sort({ timestamp: -1 })
      .limit(limit)
      .select('dip servicio evento ip timestamp fase');

    res.json({ ok: true, logs });
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener historial' });
  }
});

// ── QR universal para PlacetaID Móvil ──────────────────────────────────────
// Genera un QR con el deep link universal que abre la app directamente
app.get('/api/mobil/qr', async (req, res) => {
  try {
    const deepLink = 'placetaid-mobil://auth';
    const qrDataUrl = await QRCode.toDataURL(deepLink, {
      width: 300,
      margin: 2,
      color: { dark: '#1c005f', light: '#ffffff' }
    });
    res.json({ ok: true, qr: qrDataUrl, link: deepLink });
  } catch (err) {
    res.status(500).json({ error: 'Error al generar QR' });
  }
});

// ── SERVIR FRONTEND ───────────────────────────────────────────────────────────
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'assets', 'faviid.png'));
});

// ── INICIAR SERVIDOR ──────────────────────────────────────────────────────────
// ═════════════════════════════════════════════════════════════════════════
// VOTACIONES API — Integración con Admin-Placeta + PlacetaID Móvil
// ═════════════════════════════════════════════════════════════════════════

// Almacén en memoria para votaciones y notificaciones
// (En producción debería usar MongoDB)
const memVotaciones = new Map();

// Opciones de voto de una votación. Si no tiene opciones personalizadas,
// se usan las 3 clásicas (a favor / en contra / abstención).
function opcionesDe(v) {
  return Array.isArray(v.opciones) && v.opciones.length >= 2
    ? v.opciones
    : ['a_favor', 'en_contra', 'abstencion'];
}

// Resultado de una votación cerrada: opción ganadora (opciones personalizadas)
// o Aprobada/Rechazada (opciones clásicas).
function resultadoDe(v) {
  if (Array.isArray(v.opciones) && v.resultados) {
    const ops = opcionesDe(v);
    return ops.reduce((a, b) => (v.resultados[b] || 0) > (v.resultados[a] || 0) ? b : a, ops[0]);
  }
  return (v.aFavor || 0) > (v.enContra || 0) ? 'Aprobada' : 'Rechazada';
}
let memNotifIdCounter = 0;
const memNotificaciones = [];

function pushNotificacion(data) {
  const notif = {
    _id: String(++memNotifIdCounter),
    ...data,
    creadoEn: data.creadoEn || new Date().toISOString()
  };
  memNotificaciones.push(notif);

  // Enviar push real via FCM si está disponible
  if (firebaseAdmin && data.dip) {
    setImmediate(async () => {
      try {
        const devices = await MobileDevice.find({ dip: data.dip, activo: true }).lean();
        if (devices.length > 0) {
          const tokens = devices.map(d => d.deviceId).filter(Boolean);
          if (tokens.length > 0) {
            const message = {
              tokens,
              data: {
                type: data.tipo || 'general',
                title: data.titulo || '',
                body: data.cuerpo || '',
                id: String(notif._id),
                documentoId: data.documentoId || ''
              }
            };
            await firebaseAdmin.messaging().sendEachForMulticast(message);
          }
        }
      } catch (e) {
        console.warn('[FCM] Error sending push:', e.message);
      }
    });
  }
}

// ── Helper: obtener DIPs por grupo electoral ─────────────────────────────
async function getDIPsPorGrupo(grupo) {
  const filtro = { activo: true, bloqueado: false };
  const usuarios = await Registro.find(filtro, 'dip fechaNacimiento rol nombre apellidos').lean();

  return usuarios.filter(u => {
    const edad = u.edad !== undefined ? u.edad : (u.fechaNacimiento ? Math.floor((Date.now() - new Date(u.fechaNacimiento).getTime()) / 31557600000) : 0);
    switch (grupo) {
      case 'Junta': return ['administrador', 'moderador'].includes(u.rol);
      case '+18': return edad >= 18;
      case '16-17': return edad >= 16 && edad < 18;
      case 'Junior': return edad < 16;
      case 'Publico_General': return true;
      default: return true;
    }
  }).map(u => ({ dip: u.dip, nombre: u.nombre, apellidos: u.apellidos, edad: u.edad || 0 }));
}

// ── Inicializar votaciones de ejemplo ─────────────────────────────────
(function initVotacionesEjemplo() {
  if (memVotaciones.size > 0) return;
  const ahora = new Date();
  const manana = new Date(ahora.getTime() + 24 * 60 * 60 * 1000);
  const semana = new Date(ahora.getTime() + 7 * 24 * 60 * 60 * 1000);

  const ejemplos = [
    {
      id: 'VOT-003', titulo: 'Nuevo Cargo Directivo — Dir. Comunicación',
      descripcion: 'Elección del nuevo Director/a de Comunicación del Grupo de La Placeta',
      categoria: 'junta', grupo: 'Junta', quorum: 50,
      aFavor: 0, enContra: 0, abstenciones: 0, totalVotos: 0, totalEmitidos: 0,
      estado: 'Activa', resultado: null, reunionId: null,
      fechaCreacion: ahora.toISOString(), fechaLimite: semana.toISOString(),
      requiereQuorum: true, destinatarios: [],
      creadoEn: ahora.toISOString().slice(0, 10)
    },
    {
      id: 'VOT-004', titulo: '¿Debe la Placeta organizar un evento anual?',
      descripcion: 'Consulta ciudadana sobre la organización de un evento anual abierto a todos los ciudadanos',
      categoria: 'ciudadanos', grupo: 'Publico_General', quorum: 30,
      aFavor: 0, enContra: 0, abstenciones: 0, totalVotos: 0, totalEmitidos: 0,
      estado: 'Activa', resultado: null, reunionId: 'REU-003',
      fechaCreacion: ahora.toISOString(), fechaLimite: manana.toISOString(),
      requiereQuorum: false, destinatarios: [],
      creadoEn: ahora.toISOString().slice(0, 10)
    }
  ];
  ejemplos.forEach(e => memVotaciones.set(e.id, e));
  console.log(`  ✅ ${ejemplos.length} votaciones de ejemplo inicializadas`);
})();

// ── POST /api/admin/votaciones — Recibir votación desde Admin-Placeta ────
app.post('/api/admin/votaciones', verifyAdminApiKey, async (req, res) => {
  try {
    const { id, titulo, grupo, quorum, aFavor, enContra, abstenciones, estado, resultado, reunionId, fechaLimite, categoria, descripcion, requiereQuorum } = req.body;
    if (!id || !titulo) return res.status(400).json({ error: 'id y titulo requeridos' });
    const dipGrupo = await getDIPsPorGrupo(grupo || 'Publico_General');

    // Opciones de respuesta personalizadas (opcional; si no, las 3 clásicas).
    const opciones = Array.isArray(req.body.opciones) && req.body.opciones.length >= 2
      ? req.body.opciones.map(String)
      : ['a_favor', 'en_contra', 'abstencion'];
    const resultados = Object.fromEntries(opciones.map((o) => [o, 0]));

    // Calcular fecha límite por defecto (7 días)
    let fechaLim = fechaLimite;
    if (!fechaLim) {
      const def = new Date();
      def.setDate(def.getDate() + 7);
      fechaLim = def.toISOString();
    }

    const votacion = {
      id, titulo, descripcion: descripcion || '',
      categoria: categoria || grupo || 'General', grupo: grupo || 'Publico_General',
      quorum: quorum || 50,
      aFavor: aFavor || 0, enContra: enContra || 0, abstenciones: abstenciones || 0,
      totalVotos: (aFavor || 0) + (enContra || 0) + (abstenciones || 0),
      totalEmitidos: 0,
      opciones, resultados,
      estado: estado || 'Activa', resultado: resultado || null,
      reunionId: reunionId || null, requiereQuorum: requiereQuorum !== undefined ? requiereQuorum : true,
      fechaCreacion: new Date().toISOString(), fechaLimite: fechaLim,
      destinatarios: dipGrupo, creadoEn: new Date().toISOString().slice(0, 10)
    };
    memVotaciones.set(id, votacion);

    // Crear notificaciones para cada destinatario
    for (const d of dipGrupo) {
      pushNotificacion({
        tipo: 'votacion',
        dip: d.dip,
        titulo: `🗳️ Nueva votación: ${titulo}`,
        cuerpo: `Se ha abierto una votación para el grupo ${grupo}. Participa desde PlacetaID Móvil.`,
        votacionId: id,
        leido: false
      });
    }

    res.json({ success: true, votacion, destinatarios: dipGrupo.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/admin/votaciones — Listar votaciones ────────────────────────
app.get('/api/admin/votaciones', verifyAdminApiKey, async (req, res) => {
  res.json([...memVotaciones.values()]);
});

// ── GET /api/admin/votaciones/:id — Obtener votación ─────────────────────
app.get('/api/admin/votaciones/:id', verifyAdminApiKey, async (req, res) => {
  const v = memVotaciones.get(req.params.id);
  if (!v) return res.status(404).json({ error: 'No encontrada' });
  res.json(v);
});

// ── PUT /api/admin/votaciones/:id/cerrar — Cerrar votación ──────────────
app.put('/api/admin/votaciones/:id/cerrar', verifyAdminApiKey, async (req, res) => {
  const v = memVotaciones.get(req.params.id);
  if (!v) return res.status(404).json({ error: 'No encontrada' });
  v.estado = 'Cerrada';
  v.resultado = resultadoDe(v);
  // Notificar resultado
  for (const d of v.destinatarios || []) {
    pushNotificacion({
      tipo: 'votacion_resultado',
      dip: d.dip,
      titulo: `📊 Resultado votación: ${v.titulo}`,
      cuerpo: `La votación "${v.titulo}" ha sido cerrada. Resultado: ${v.resultado}`,
      votacionId: v.id,
      leido: false
    });
  }
  res.json({ success: true, votacion: v });
});

// ═════════════════════════════════════════════════════════════════════════
// DOCUMENTOS API — Firma electrónica filtrada por DIP
// ═════════════════════════════════════════════════════════════════════════

const memDocumentos = new Map();

// ── Helper: sincronizar firma a admin-placeta ──────────────────────────
// ── Registrar conexión RSP en admin-placeta ────────────────────────────
async function rspRegistrarPlaceta(entidad, tipo, endpoint, dip = '') {
  try {
    const ADMIN_API = process.env.ADMIN_API_URL || 'https://admin-placeta.vercel.app';
    const API_KEY = process.env.DOCS_API_KEY || 'docs-shared-key-2026';
    const url = `${ADMIN_API}/rsp/api/conexiones/registrar?api_key=${API_KEY}`;
    const resp = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        entidad: entidad || 'votaciones',
        tipo,
        endpoint,
        usuario: 'placetaid-server',
        dip: dip || '',
        detalle: 'Votación desde PlacetaID Móvil'
      }),
      signal: AbortSignal.timeout(10000)
    });
    if (!resp.ok) {
      const text = await resp.text().catch(() => 'sin cuerpo');
      console.warn(`[RSP] Admin respondió ${resp.status}: ${text.slice(0,100)}`);
    } else {
      console.log(`[RSP] ✅ Conexión registrada: ${tipo} ${endpoint}`);
    }
  } catch (e) {
    console.error('[RSP] Error registrando conexión en admin-placeta:', e.message);
  }
}

async function syncFirmaAAdmin(doc, dip, firmaBase64) {
  try {
    const ADMIN_API = process.env.ADMIN_API_URL || 'https://admin-placeta.vercel.app';
    const API_KEY = process.env.DOCS_API_KEY || 'docs-shared-key-2026';
    const entidad = doc.entidad || 'banco';
    await fetch(`${ADMIN_API}/publico/${entidad}/documentos/${doc.id}/firmar?api_key=${API_KEY}`, {
      method: 'PUT',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({
        estado: 'firmado', firmado: true,
        datos: { firmadoPor: dip, fechaFirma: new Date().toISOString(), ...(firmaBase64?{firma_base64:firmaBase64,firmaImagen:firmaBase64}:{}) }
      }),
      signal: AbortSignal.timeout(5000)
    });
  } catch (e) { console.error('[Sync] Error syncing to admin-placeta:', e.message); }
}

// ── POST /api/admin/documentos — Recibir documento para firma ────────────
app.post('/api/admin/documentos', verifyAdminApiKey, async (req, res) => {
  try {
    const { id, titulo, tipo, entidad, destinatariosDIP, contenido, csv } = req.body;
    if (!id || !titulo) return res.status(400).json({ error: 'id y titulo requeridos' });

    // Validar que los DIPs destino existen
    const dipsValidos = [];
    if (destinatariosDIP?.length) {
      for (const dip of destinatariosDIP) {
        const user = await Registro.findOne({ dip, activo: true }).lean();
        if (user) dipsValidos.push({ dip: user.dip, nombre: user.nombre, firmado: false, fechaFirma: null });
      }
    }

    const doc = {
      _id: id, id, titulo, tipo: tipo || 'documento', entidad: entidad || 'administracion',
      csv: csv || `CSV-${Date.now().toString(36).toUpperCase()}`,
      estado: 'Pendiente_Firma', destinatarios: dipsValidos,
      contenido: contenido || null, creadoEn: new Date().toISOString(),
      firmadoEn: null
    };

    // Guardar en memoria
    memDocumentos.set(id, doc);

    // Notificar a cada destinatario
    for (const d of dipsValidos) {
      pushNotificacion({
        tipo: 'documento',
        dip: d.dip,
        titulo: `📄 Documento pendiente: ${titulo}`,
        cuerpo: `Tienes un documento pendiente de firma: ${titulo} (${tipo || 'documento'}). Ábrelo desde PlacetaID Móvil.`,
        documentoId: id,
        leido: false
      });
    }

    res.json({ success: true, documento: doc, notificacionesEnviadas: dipsValidos.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/admin/documentos — Listar documentos ────────────────────────
app.get('/api/admin/documentos', verifyAdminApiKey, async (req, res) => {
  res.json([...memDocumentos.values()]);
});

// ── GET /api/admin/documentos/:id — Obtener documento ────────────────────
app.get('/api/admin/documentos/:id', verifyAdminApiKey, async (req, res) => {
  const d = memDocumentos.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'No encontrado' });
  res.json(d);
});

// ── POST /api/admin/documentos/:id/firmar — Firmar documento (admin) ────
app.post('/api/admin/documentos/:id/firmar', verifyAdminApiKey, async (req, res) => {
  const d = memDocumentos.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'No encontrado' });
  const { dip, bypass } = req.body;
  if (!dip) return res.status(400).json({ error: 'DIP requerido' });

  const dest = d.destinatarios.find(dd => dd.dip === dip);
  if (!dest && !bypass) return res.status(400).json({ error: 'DIP no está en la lista de destinatarios' });

  if (bypass) {
    // Marcar todos como firmados
    d.destinatarios = d.destinatarios.map(dd => ({
      ...dd, firmado: true, fechaFirma: new Date().toISOString()
    }));
  } else {
    dest.firmado = true;
    dest.fechaFirma = new Date().toISOString();
  }

  // Verificar si todos firmaron
  const todosFirmados = d.destinatarios.every(dd => dd.firmado);
  if (todosFirmados) {
    d.estado = 'Oficial';
    d.firmadoEn = new Date().toISOString();
  }

  res.json({ success: true, documento: d });
});

// ═════════════════════════════════════════════════════════════════════════
// PLACETAID MÓVIL — Votaciones y Documentos
// ═════════════════════════════════════════════════════════════════════════

// ── Registro oficial de votos (para tracking anti-fraude) ──────────────
const memRegistroVotos = new Map();
let regVotoCounter = 0;

function generarHashVoto(votacionId, dip, voto, timestamp) {
  const payload = `${votacionId}:${dip}:${voto}:${timestamp}:placetaid-vote-secret-2026`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function calcularTiempoRestante(fechaLimite) {
  if (!fechaLimite) return null;
  const ahora = new Date();
  const limite = new Date(fechaLimite);
  const diff = limite.getTime() - ahora.getTime();
  if (diff <= 0) return { expirada: true, dias: 0, horas: 0, minutos: 0, total: 0 };
  return {
    expirada: false,
    dias: Math.floor(diff / (1000 * 60 * 60 * 24)),
    horas: Math.floor((diff % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60)),
    minutos: Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60)),
    total: diff
  };
}

function debeSerAnonimo(votacion) {
  if (!votacion.fechaLimite) return false;
  if (votacion.categoria === 'junta') return false;
  const limite = new Date(votacion.fechaLimite);
  const ahora = new Date();
  const diff = ahora.getTime() - limite.getTime();
  return diff > 30 * 24 * 60 * 60 * 1000;
}

// ── GET /api/mobil/votaciones/:dip — Votaciones activas para un DIP ──────
app.get('/api/mobil/votaciones/:dip', async (req, res) => {
  try {
    const user = await Registro.findOne({ dip: req.params.dip }).lean();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const edad = user.edad !== undefined ? user.edad : (user.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
    const rol = user.rol || 'miembro';

    const votaciones = [...memVotaciones.values()].filter(v => {
      if (v.estado !== 'Activa') return false;
      switch (v.grupo) {
        case 'Junta': return ['administrador', 'moderador'].includes(rol);
        case '+18': return edad >= 18;
        case '16-17': return edad >= 16 && edad < 18;
        case 'Junior': return edad < 16;
        case 'Publico_General': return true;
        default: return true;
      }
    }).map(v => ({
      ...v,
      tiempoRestante: calcularTiempoRestante(v.fechaLimite),
      esAnonimo: debeSerAnonimo(v)
    }));
    res.json(votaciones);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/votaciones/pendientes/:dip — Votaciones pendientes (no votadas) ─
app.get('/api/mobil/votaciones/pendientes/:dip', async (req, res) => {
  try {
    const user = await Registro.findOne({ dip: req.params.dip }).lean();
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const edad = user.edad !== undefined ? user.edad : (user.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
    const rol = user.rol || 'miembro';

    const yaVotadas = new Set(
      [...memRegistroVotos.values()]
        .filter(r => r.dip === req.params.dip)
        .map(r => r.votacionId)
    );

    const pendientes = [...memVotaciones.values()]
      .filter(v => v.estado === 'Activa' && !yaVotadas.has(v.id))
      .filter(v => {
        switch (v.grupo) {
          case 'Junta': return ['administrador', 'moderador'].includes(rol);
          case '+18': return edad >= 18;
          case '16-17': return edad >= 16 && edad < 18;
          case 'Junior': return edad < 16;
          case 'Publico_General': return true;
          default: return true;
        }
      })
      .map(v => ({
        ...v,
        tiempoRestante: calcularTiempoRestante(v.fechaLimite),
        esAnonimo: debeSerAnonimo(v),
        yaVoto: false
      }));

    res.json(pendientes);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/votaciones/activas — Todas las votaciones activas ──────
app.get('/api/mobil/votaciones/activas', async (req, res) => {
  const activas = [...memVotaciones.values()]
    .filter(v => v.estado === 'Activa')
    .map(v => ({ ...v, tiempoRestante: calcularTiempoRestante(v.fechaLimite) }));
  res.json(activas);
});

// ── GET /api/mobil/votaciones/:id — Detalle de una votación ──────────────
app.get('/api/mobil/votaciones/detalle/:id', async (req, res) => {
  const v = memVotaciones.get(req.params.id);
  if (!v) return res.status(404).json({ error: 'No encontrada' });
  const esAnonimo = debeSerAnonimo(v);
  const votos = [...memRegistroVotos.values()].filter(r => r.votacionId === v.id);
  res.json({
    ...v,
    tiempoRestante: calcularTiempoRestante(v.fechaLimite),
    esAnonimo,
    votos: esAnonimo ? votos.map(r => ({
      id: r.id, hash: r.hash, oficial: r.oficial, timestamp: r.timestamp,
      dip: r.categoria === 'junta' ? r.dip : '***',
      nombre: r.categoria === 'junta' ? r.nombre : 'Voto anónimo',
      voto: r.voto
    })) : votos
  });
});

// ── POST /api/mobil/votaciones/ejercer — Emitir voto (body con votacionId) ─
app.post('/api/mobil/votaciones/ejercer', async (req, res) => {
  try {
    const { dip, nombre, voto, votacionId } = req.body;
    const idVotacion = votacionId;
    const v = memVotaciones.get(idVotacion);

    if (!v) return res.status(404).json({ error: 'Votación no encontrada' });
    if (v.estado !== 'Activa') return res.status(400).json({ error: 'Esta votación ya está cerrada' });
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });
    const opcionesValidas = opcionesDe(v);
    if (!voto || !opcionesValidas.includes(voto)) {
      return res.status(400).json({ error: `Voto inválido. Opciones válidas: ${opcionesValidas.join(', ')}` });
    }

    // Verificar fecha límite
    if (v.fechaLimite) {
      const tiempo = calcularTiempoRestante(v.fechaLimite);
      if (tiempo && tiempo.expirada) {
        v.estado = 'Cerrada';
        v.resultado = (v.aFavor || 0) > (v.enContra || 0) ? 'Aprobada' : 'Rechazada';
        return res.status(400).json({ error: 'Votación expirada', estado: 'Cerrada' });
      }
    }

    // Verificar categoría
    const user = await Registro.findOne({ dip }).lean();
    const edad = user?.edad !== undefined ? user.edad : (user?.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
    const rol = user?.rol || 'miembro';
    let puedeVotar = true;
    switch (v.grupo) {
      case 'Junta': puedeVotar = ['administrador', 'moderador'].includes(rol); break;
      case '+18': puedeVotar = edad >= 18; break;
      case '16-17': puedeVotar = edad >= 16 && edad < 18; break;
      case 'Junior': puedeVotar = edad < 16; break;
      default: puedeVotar = true;
    }
    if (!puedeVotar) return res.status(403).json({ error: `No tienes derecho a voto en esta categoría` });

    // Verificar voto duplicado
    const yaVoto = [...memRegistroVotos.values()].some(r => r.votacionId === idVotacion && r.dip === dip);
    if (yaVoto) return res.status(409).json({ error: 'Ya has ejercido tu voto en esta votación' });

    // Registrar voto
    const regId = 'REG-' + String(++regVotoCounter).padStart(5, '0');
    const timestamp = new Date().toISOString();
    const hash = generarHashVoto(idVotacion, dip, voto, timestamp);

    const registro = {
      id: regId, votacionId: idVotacion, dip, nombre: nombre || dip,
      categoria: v.categoria || v.grupo || 'General', voto, timestamp, hash, oficial: true
    };
    memRegistroVotos.set(regId, registro);

    // Actualizar conteo
    if (voto === 'a_favor') v.aFavor = (v.aFavor || 0) + 1;
    else if (voto === 'en_contra') v.enContra = (v.enContra || 0) + 1;
    else if (voto === 'abstencion') v.abstenciones = (v.abstenciones || 0) + 1;
    if (!v.resultados) v.resultados = {};
    v.resultados[voto] = (v.resultados[voto] || 0) + 1;
    v.totalVotos = (v.totalVotos || 0) + 1;
    v.totalEmitidos = [...memRegistroVotos.values()].filter(r => r.votacionId === idVotacion).length;

    // Registrar en RSP (no bloqueante)
    rspRegistrarPlaceta(v.categoria || 'votaciones', 'modificacion', `POST /mobil/votaciones/${idVotacion}/ejercer`, dip);

    res.json({
      success: true,
      message: 'Voto registrado oficialmente',
      registro: { id: regId, hash, timestamp, oficial: true },
      votacion: { id: idVotacion, aFavor: v.aFavor, enContra: v.enContra, abstenciones: v.abstenciones, totalVotos: v.totalVotos, resultados: v.resultados }
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/votaciones/:id/ejercer — Emitir voto (path con ID) ──
app.post('/api/mobil/votaciones/:id/ejercer', async (req, res) => {
  // Reuse the ejercer logic by forwarding to the body-based handler
  req.body = { ...req.body, votacionId: req.params.id };
  // Forward to existing handler by calling the route logic directly
  const { dip, nombre, voto, votacionId } = req.body;
  const idVotacion = votacionId;
  try {
    if (!idVotacion) return res.status(400).json({ error: 'ID de votación requerido' });
    const v = memVotaciones.get(idVotacion);
    if (!v) return res.status(404).json({ error: 'Votación no encontrada' });
    if (v.estado !== 'Activa') return res.status(400).json({ error: 'Esta votación ya está cerrada' });
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });
    const opcionesValidas = opcionesDe(v);
    if (!voto || !opcionesValidas.includes(voto)) {
      return res.status(400).json({ error: `Voto inválido. Opciones válidas: ${opcionesValidas.join(', ')}` });
    }
    if (v.fechaLimite) {
      const tiempo = calcularTiempoRestante(v.fechaLimite);
      if (tiempo && tiempo.expirada) {
        v.estado = 'Cerrada';
        v.resultado = (v.aFavor || 0) > (v.enContra || 0) ? 'Aprobada' : 'Rechazada';
        return res.status(400).json({ error: 'Votación expirada', estado: 'Cerrada' });
      }
    }
    const user = await Registro.findOne({ dip }).lean();
    const edad = user?.edad !== undefined ? user.edad : (user?.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
    const rol = user?.rol || 'miembro';
    let puedeVotar = true;
    switch (v.grupo) {
      case 'Junta': puedeVotar = ['administrador', 'moderador'].includes(rol); break;
      case '+18': puedeVotar = edad >= 18; break;
      case '16-17': puedeVotar = edad >= 16 && edad < 18; break;
      case 'Junior': puedeVotar = edad < 16; break;
      default: puedeVotar = true;
    }
    if (!puedeVotar) return res.status(403).json({ error: 'No tienes derecho a voto en esta categoría' });
    const yaVoto = [...memRegistroVotos.values()].some(r => r.votacionId === idVotacion && r.dip === dip);
    if (yaVoto) return res.status(409).json({ error: 'Ya has ejercido tu voto en esta votación' });
    const regId = 'REG-' + String(++regVotoCounter).padStart(5, '0');
    const timestamp = new Date().toISOString();
    const hash = generarHashVoto(idVotacion, dip, voto, timestamp);
    const registro = { id: regId, votacionId: idVotacion, dip, nombre: nombre || dip, categoria: v.categoria || v.grupo || 'General', voto, timestamp, hash, oficial: true };
    memRegistroVotos.set(regId, registro);
    if (voto === 'a_favor') v.aFavor = (v.aFavor || 0) + 1;
    else if (voto === 'en_contra') v.enContra = (v.enContra || 0) + 1;
    else if (voto === 'abstencion') v.abstenciones = (v.abstenciones || 0) + 1;
    if (!v.resultados) v.resultados = {};
    v.resultados[voto] = (v.resultados[voto] || 0) + 1;
    v.totalVotos = (v.totalVotos || 0) + 1;
    v.totalEmitidos = [...memRegistroVotos.values()].filter(r => r.votacionId === idVotacion).length;
    // Registrar en RSP (no bloqueante)
    rspRegistrarPlaceta(v.categoria || 'votaciones', 'modificacion', `POST /mobil/votaciones/${idVotacion}/ejercer`, dip);
    res.json({ success: true, message: 'Voto registrado oficialmente', registro: { id: regId, hash, timestamp, oficial: true }, votacion: { id: idVotacion, aFavor: v.aFavor, enContra: v.enContra, abstenciones: v.abstenciones, totalVotos: v.totalVotos, resultados: v.resultados } });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/votaciones/historial/:dip — Historial de votos ────────
app.get('/api/mobil/votaciones/historial/:dip', async (req, res) => {
  try {
    const todasVotaciones = [...memVotaciones.values()];
    const historial = todasVotaciones.map(v => {
      const esAnonimo = debeSerAnonimo(v);
      const misVotos = [...memRegistroVotos.values()].filter(r => r.votacionId === v.id);
      const miVoto = misVotos.find(r => r.dip === req.params.dip);
      return {
        id: v.id, titulo: v.titulo, descripcion: v.descripcion,
        categoria: v.categoria || v.grupo, grupo: v.grupo,
        estado: v.estado, resultado: v.resultado,
        fechaCreacion: v.creadoEn || v.fechaCreacion, fechaLimite: v.fechaLimite,
        reunionId: v.reunionId, aFavor: v.aFavor, enContra: v.enContra,
        abstenciones: v.abstenciones, totalVotos: v.totalVotos, totalEmitidos: v.totalEmitidos,
        opciones: v.opciones || null, resultados: v.resultados || null,
        miVoto: miVoto ? { voto: miVoto.voto, timestamp: miVoto.timestamp, hash: miVoto.hash, oficial: miVoto.oficial } : null,
        esAnonimo,
        votos: esAnonimo ? [] : misVotos.map(r => ({
          dip: r.categoria === 'junta' ? r.dip : '***',
          nombre: r.categoria === 'junta' ? r.nombre : '***',
          voto: r.voto, hash: r.hash
        }))
      };
    }).sort((a, b) => (b.fechaCreacion || '').localeCompare(a.fechaCreacion || ''));
    res.json(historial);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/votaciones/verificar/:votacionId/:dip — Verificar voto ─
app.get('/api/mobil/votaciones/verificar/:votacionId/:dip', async (req, res) => {
  const registro = [...memRegistroVotos.values()]
    .find(r => r.votacionId === req.params.votacionId && r.dip === req.params.dip);
  if (!registro) return res.status(404).json({ error: 'Voto no encontrado' });
  const hashVerificado = generarHashVoto(registro.votacionId, registro.dip, registro.voto, registro.timestamp);
  const integro = hashVerificado === registro.hash;
  res.json({
    verificado: integro, oficial: registro.oficial,
    timestamp: registro.timestamp, hash: registro.hash,
    hashRecalculado: hashVerificado, voto: registro.voto, integro
  });
});

// ── POST /api/mobil/multi/votaciones/activas — Multi-identidad votos activos ─
app.post('/api/mobil/multi/votaciones/activas', async (req, res) => {
  const { dips } = req.body;
  if (!dips || !Array.isArray(dips)) return res.json([]);
  try {
    const usuarios = await Registro.find({ dip: { $in: dips } }).lean();
    const resultado = [];
    for (const user of usuarios) {
      const edad = user.edad !== undefined ? user.edad : (user.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
      const rol = user.rol || 'miembro';
      const yaVotadas = new Set([...memRegistroVotos.values()].filter(r => r.dip === user.dip).map(r => r.votacionId));
      const pendientes = [...memVotaciones.values()]
        .filter(v => v.estado === 'Activa' && !yaVotadas.has(v.id))
        .filter(v => {
          switch (v.grupo) {
            case 'Junta': return ['administrador', 'moderador'].includes(rol);
            case '+18': return edad >= 18;
            default: return true;
          }
        })
        .map(v => ({
          ...v, identidad: user.dip, identidadNombre: `${user.nombre || ''} ${user.apellidos || ''}`.trim(),
          tiempoRestante: calcularTiempoRestante(v.fechaLimite)
        }));
      resultado.push(...pendientes);
    }
    res.json(resultado);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/multi/votaciones/historial — Multi-identidad historial ─
app.post('/api/mobil/multi/votaciones/historial', async (req, res) => {
  const { dips } = req.body;
  if (!dips || !Array.isArray(dips)) return res.json([]);
  try {
    const todasVotaciones = [...memVotaciones.values()];
    const resultado = [];
    for (const dip of dips) {
      for (const v of todasVotaciones) {
        const miVoto = [...memRegistroVotos.values()].find(r => r.votacionId === v.id && r.dip === dip);
        if (miVoto) {
          resultado.push({
            id: v.id, titulo: v.titulo, identidad: dip,
            grupo: v.grupo, estado: v.estado, resultado: v.resultado,
            aFavor: v.aFavor, enContra: v.enContra, abstenciones: v.abstenciones,
            miVoto: { voto: miVoto.voto, timestamp: miVoto.timestamp, hash: miVoto.hash }
          });
        }
      }
    }
    res.json(resultado);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/documentos/:dip — Documentos pendientes para un DIP ───
app.get('/api/mobil/documentos/:dip', async (req, res) => {
  const docs = [...memDocumentos.values()].filter(d =>
    d.estado !== 'Oficial' && d.destinatarios.some(dd => dd.dip === req.params.dip && !dd.firmado)
  );
  res.json(docs);
});

// ── POST /api/mobil/documentos/:id/firmar — Firmar documento desde móvil ─
app.post('/api/mobil/documentos/:id/firmar', async (req, res) => {
  try {
    const d = memDocumentos.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'No encontrado' });
    const { dip } = req.body;
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });
    const dest = d.destinatarios.find(dd => dd.dip === dip);
    if (!dest) return res.status(400).json({ error: 'No tienes documentos pendientes con este ID' });
    if (dest.firmado) return res.status(400).json({ error: 'Ya has firmado este documento' });
    dest.firmado = true;
    dest.fechaFirma = new Date().toISOString();
    // Guardar firma manuscrita si se envió
    if (req.body.firma_base64) dest.firmaBase64 = req.body.firma_base64;
    const todosFirmados = d.destinatarios.every(dd => dd.firmado);
    if (todosFirmados) { d.estado = 'Oficial'; d.firmadoEn = new Date().toISOString(); }
    pushNotificacion({ tipo:'documento_firmado', dip, titulo:`📝 Has firmado: ${d.titulo}`, cuerpo:`Has firmado electrónicamente el documento "${d.titulo}". Estado actual: ${d.estado}`, documentoId:d.id, leido:false });
    // Sincronizar firma a admin-placeta
    syncFirmaAAdmin(d, dip, req.body.firma_base64);
    res.json({ success:true, estado:d.estado, firmado:true, firmaRecibida:!!req.body.firma_base64 });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/documentos/:id/firmar-con-firma — Firmar con firma manuscrita ─
app.post('/api/mobil/documentos/:id/firmar-con-firma', async (req, res) => {
  try {
    const d = memDocumentos.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'No encontrado' });
    const { dip, firma_base64 } = req.body;
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });
    if (!firma_base64) return res.status(400).json({ error: 'firma_base64 requerida' });
    const dest = d.destinatarios.find(dd => dd.dip === dip);
    if (!dest) return res.status(400).json({ error: 'No tienes documentos pendientes con este ID' });
    if (dest.firmado) return res.status(400).json({ error: 'Ya has firmado este documento' });
    dest.firmado = true;
    dest.fechaFirma = new Date().toISOString();
    dest.firmaBase64 = firma_base64;
    const todosFirmados = d.destinatarios.every(dd => dd.firmado);
    if (todosFirmados) { d.estado = 'Oficial'; d.firmadoEn = new Date().toISOString(); }
    pushNotificacion({ tipo:'documento_firmado', dip, titulo:`📝 Has firmado: ${d.titulo}`, cuerpo:`Has firmado electrónicamente el documento "${d.titulo}" con firma manuscrita. Estado: ${d.estado}`, documentoId:d.id, leido:false });
    syncFirmaAAdmin(d, dip, firma_base64);
    res.json({ success:true, estado:d.estado, firmado:true, firmaRecibida:true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/documentos/:id/rechazar — Rechazar documento desde móvil ─
app.post('/api/mobil/documentos/:id/rechazar', async (req, res) => {
  try {
    const d = memDocumentos.get(req.params.id);
    if (!d) return res.status(404).json({ error: 'No encontrado' });
    const { dip, motivo } = req.body;
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });

    const dest = d.destinatarios.find(dd => dd.dip === dip);
    if (!dest) return res.status(400).json({ error: 'No tienes documentos pendientes con este ID' });
    if (dest.firmado) return res.status(400).json({ error: 'Ya has firmado este documento' });

    dest.rechazado = true;
    dest.fechaRechazo = new Date().toISOString();
    dest.motivoRechazo = motivo || 'Sin motivo especificado';
    d.estado = 'Rechazado';
    d.motivoRechazoGlobal = motivo || 'Rechazado por un firmante';

    // Notificar a admin
    pushNotificacion({
      tipo: 'documento_rechazado',
      dip: 'ADMIN',
      titulo: `❌ Documento rechazado: ${d.titulo}`,
      cuerpo: `El usuario ${dip} ha rechazado "${d.titulo}". Motivo: ${dest.motivoRechazo}`,
      documentoId: d.id, leido: false
    });

    res.json({ success: true, estado: 'Rechazado', rechazado: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── GET /api/mobil/notificaciones/:dip — Notificaciones para un DIP ──────
app.get('/api/mobil/notificaciones/:dip', async (req, res) => {
  const notifs = memNotificaciones
    .filter(n => n.dip === req.params.dip)
    .sort((a, b) => new Date(b.creadoEn) - new Date(a.creadoEn))
    .slice(0, 50);
  res.json(notifs);
});

// ── POST /api/mobil/notificaciones/leer — Marcar notificación como leída ─
app.post('/api/mobil/notificaciones/leer', async (req, res) => {
  const { notificacionId } = req.body;
  const n = memNotificaciones.find(n => n._id === notificacionId);
  if (n) n.leido = true;
  res.json({ success: true });
});

// ═════════════════════════════════════════════════════════════════════════
// MULTI-IDENTIDAD — Consultas que aceptan varios DIPs a la vez
// ═════════════════════════════════════════════════════════════════════════

// ── POST /api/mobil/multi/pending — Autorizaciones pendientes de varios DIPs ─
app.post('/api/mobil/multi/pending', async (req, res) => {
  try {
    const { dips } = req.body;
    if (!dips || !Array.isArray(dips) || dips.length === 0) return res.status(400).json({ error: 'Array de DIPs requerido' });
    const resultados = [];
    for (const dip of dips) {
      const requests = await AuthRequest.find({ dip, estado: 'pending' }).sort({ creadoEn: -1 }).limit(10).lean();
      for (const r of requests) {
        resultados.push({ ...r, identidad: dip });
      }
    }
    res.json(resultados.sort((a, b) => new Date(b.creadoEn) - new Date(a.creadoEn)));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/multi/votaciones — Votaciones activas para varios DIPs ─
app.post('/api/mobil/multi/votaciones', async (req, res) => {
  try {
    const { dips } = req.body;
    if (!dips || !Array.isArray(dips)) return res.status(400).json({ error: 'Array de DIPs requerido' });
    const usuarios = await Registro.find({ dip: { $in: dips }, activo: true }, 'dip fechaNacimiento rol nombre apellidos').lean();
    const resultados = [];
    const votaciones = [...memVotaciones.values()].filter(v => v.estado === 'Activa');
    for (const user of usuarios) {
      const edad = user.edad !== undefined ? user.edad : (user.fechaNacimiento ? Math.floor((Date.now() - new Date(user.fechaNacimiento).getTime()) / 31557600000) : 0);
      const rol = user.rol || 'miembro';
      for (const v of votaciones) {
        let aplica = false;
        switch (v.grupo) {
          case 'Junta': aplica = ['administrador', 'moderador'].includes(rol); break;
          case '+18': aplica = edad >= 18; break;
          case '16-17': aplica = edad >= 16 && edad < 18; break;
          case 'Junior': aplica = edad < 16; break;
          case 'Publico_General': aplica = true; break;
          default: aplica = true;
        }
        if (aplica) resultados.push({ ...v, identidad: user.dip, identidadNombre: user.nombre });
      }
    }
    res.json(resultados);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/multi/documentos — Documentos pendientes para varios DIPs ─
app.post('/api/mobil/multi/documentos', async (req, res) => {
  try {
    const { dips, todos } = req.body;
    
    // 1. Documentos en memoria
    const docs = [...memDocumentos.values()];
    const idsEnMemoria = new Set(docs.map(d => d.id || d._id));

    // 2. Siempre sincronizar desde admin-placeta
    try {
      const ADMIN_API = process.env.ADMIN_API_URL || 'https://admin-placeta.vercel.app';
      const API_KEY = process.env.DOCS_API_KEY || 'docs-shared-key-2026';
      const r = await fetch(`${ADMIN_API}/publico/banco/documentos?api_key=${API_KEY}`);
      if (r.ok) {
        for (const ad of (await r.json()).documentos || []) {
          if (idsEnMemoria.has(ad.id)) continue;
          const dipDoc = ad.datos?.dip || '';
          if (!dipDoc || ad.createdBy === 'sistema') continue;
          let nombre = '';
          try { const u = await Registro.findOne({ dip: dipDoc }, 'nombre apellidos').lean(); if (u) nombre = `${u.nombre} ${u.apellidos || ''}`.trim(); } catch {}
          const doc = {
            _id: ad.id, id: ad.id, titulo: ad.titulo || 'Documento',
            tipo: ad.tipo || 'documento', entidad: 'banco',
            csv: ad.hash || `CSV-${(ad.id||'').slice(0,8).toUpperCase()}`,
            estado: ad.estado === 'firmado' ? 'Oficial' : 'Pendiente_Firma',
            destinatarios: [{ dip: dipDoc, nombre: nombre || dipDoc, firmado: ad.estado === 'firmado', fechaFirma: ad.datos?.fechaFirma || null }],
            contenido: null, creadoEn: ad.createdAt || new Date().toISOString(), firmadoEn: ad.datos?.fechaFirma || null
          };
          memDocumentos.set(ad.id, doc);
          docs.push(doc);
        }
      }
    } catch (e) { console.error('[Docs] Error fetching from admin-placeta:', e.message); }
    
    // 3. Filtrar SIEMPRE por los DIPs del dispositivo (nunca documentos ajenos).
    //    `todos` solo añade los ya firmados/Oficiales al listado (historial).
    if (!dips || !Array.isArray(dips) || dips.length === 0) {
      return res.status(400).json({ error: 'Array de DIPs requerido' });
    }
    const filtrados = docs.filter(d => {
      const me = d.destinatarios?.find(dd => dips.includes(dd.dip));
      if (!me) return false;
      if (todos === true) return true;                                  // historial del usuario
      return d.estado !== 'Oficial' && !me.firmado && !me.rechazado;    // solo pendientes
    });
    
    const resultados = filtrados.map(d => {
      const miDest = d.destinatarios?.[0] || {};
      return { ...d, identidad: miDest.dip || '', identidadNombre: miDest.nombre || '' };
    });
    res.json(resultados);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/multi/documentos/todos — Todos los docs (historial) ─
app.post('/api/mobil/multi/documentos/todos', async (req, res) => {
  try {
    const { dips, todos } = req.body;
    if (!dips || !Array.isArray(dips) || dips.length === 0) {
      return res.status(400).json({ error: 'Array de DIPs requerido' });
    }
    let docs = [...memDocumentos.values()];
    if (docs.length < 10) {
      try {
        const ADMIN_API = process.env.ADMIN_API_URL || 'https://admin-placeta.vercel.app';
        const API_KEY = process.env.DOCS_API_KEY || 'docs-shared-key-2026';
        const r = await fetch(`${ADMIN_API}/publico/banco/documentos?api_key=${API_KEY}`);
        if (r.ok) {
          for (const ad of (await r.json()).documentos || []) {
            if (memDocumentos.has(ad.id)) continue;
            const dipDoc = ad.datos?.dip || '';
            if (!dipDoc || ad.createdBy === 'sistema') continue;
            let nombre = '';
            try { const u = await Registro.findOne({ dip: dipDoc }, 'nombre apellidos').lean(); if (u) nombre = `${u.nombre} ${u.apellidos || ''}`.trim(); } catch {}
            memDocumentos.set(ad.id, { _id:ad.id, id:ad.id, titulo:ad.titulo||'Documento', tipo:ad.tipo||'documento', entidad:'banco', csv:ad.hash||`CSV-${(ad.id||'').slice(0,8).toUpperCase()}`, estado:ad.estado==='firmado'?'Oficial':'Pendiente_Firma', destinatarios:[{dip:dipDoc, nombre:nombre||dipDoc, firmado:ad.estado==='firmado', fechaFirma:ad.datos?.fechaFirma||null}], contenido:null, creadoEn:ad.createdAt||new Date().toISOString(), firmadoEn:ad.datos?.fechaFirma||null });
            docs.push(memDocumentos.get(ad.id));
          }
        }
      } catch {}
    }
    const filtrados = docs.filter(d => d.destinatarios?.some(dd => dips.includes(dd.dip)));
    const resultados = filtrados.map(d => { const m = d.destinatarios?.[0] || {}; return {...d, identidad:m.dip||'', identidadNombre:m.nombre||''}; });
    resultados.sort((a,b) => new Date(b.creadoEn||0)-new Date(a.creadoEn||0));
    res.json(resultados);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── POST /api/mobil/multi/notificaciones — Notificaciones para varios DIPs ─
app.post('/api/mobil/multi/notificaciones', async (req, res) => {
  const { dips } = req.body;
  if (!dips || !Array.isArray(dips)) return res.json([]);
  const notifs = memNotificaciones
    .filter(n => dips.includes(n.dip))
    .sort((a, b) => new Date(b.creadoEn) - new Date(a.creadoEn))
    .slice(0, 100);
  res.json(notifs);
});

// ── POST /api/mobil/multi/documentos/:id/contenido — Contenido de documento ─
// Para previsualizar antes de firmar. SOLO si el documento es de uno de los DIPs.
app.post('/api/mobil/multi/documentos/:id/contenido', async (req, res) => {
  const { dips } = req.body || {};
  const d = memDocumentos.get(req.params.id);
  if (!d) return res.status(404).json({ error: 'No encontrado' });
  if (!dips || !Array.isArray(dips) || dips.length === 0 ||
      !d.destinatarios?.some(dd => dips.includes(dd.dip))) {
    return res.status(403).json({ error: 'Sin acceso a este documento' });
  }
  // Devolver el contenido del documento (URL del PDF o contenido base64)
  res.json({
    id: d.id, titulo: d.titulo, tipo: d.tipo, csv: d.csv,
    contenido: d.contenido || null,
    estado: d.estado,
    destinatarios: d.destinatarios
  });
});

// ═════════════════════════════════════════════════════════════════════════
// ADMIN-PLACETA BRIDGE — Proxy a PlacetaID para documentos/votaciones
// ═════════════════════════════════════════════════════════════════════════

// ── GET /api/admin/notificaciones — Todas las notificaciones ─────────────
app.get('/api/admin/notificaciones', verifyAdminApiKey, async (req, res) => {
  const { dip, tipo, leido } = req.query;
  let filtradas = [...memNotificaciones];
  if (dip) filtradas = filtradas.filter(n => n.dip === dip);
  if (tipo) filtradas = filtradas.filter(n => n.tipo === tipo);
  if (leido !== undefined) filtradas = filtradas.filter(n => n.leido === (leido === 'true'));
  res.json(filtradas.sort((a, b) => new Date(b.creadoEn) - new Date(a.creadoEn)).slice(0, 100));
});

// ── GET /api/admin/grupos/:grupo/dips — Listar DIPs por grupo electoral ──
app.get('/api/admin/grupos/:grupo/dips', verifyAdminApiKey, async (req, res) => {
  try {
    const dips = await getDIPsPorGrupo(req.params.grupo);
    res.json({ grupo: req.params.grupo, total: dips.length, dips });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Catch-all for SPA (DEBE ir al final, después de todas las rutas)
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── Global error handler ─────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('❌ Unhandled error:', err?.message || err);
  res.status(500).json({ error: 'Error interno del servidor', detail: err?.message });
});

// ── Unhandled promise rejections ────────────────────────────────────────
process.on('unhandledRejection', (reason, promise) => {
  console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
});

// ── Uncaught exceptions (prevent crash) ─────────────────────────────────
process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err?.message || err);
  console.error(err?.stack);
});

// En desarrollo local, executar: npm start
if (require.main === module) {
  // Inicializar Firebase (si hay credenciales)
  initFirebase();
  // Arrancar servidor inmediatamente, sin esperar a MongoDB
  app.listen(PORT, () => {
    console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
    // Conectar a MongoDB en segundo plano
    connectToDatabase().catch(err => {
      console.error('❌ Error conectando a MongoDB:', err);
    });
  });
}

module.exports = app;
