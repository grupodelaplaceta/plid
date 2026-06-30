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

async function connectToDatabase() {
  if (isConnected) return;

  try {
    console.log('🔌 MongoDB connection attempt...');
    console.log('   MONGO_URI:', process.env.MONGO_URI ? `${process.env.MONGO_URI.substring(0, 40)}...` : 'NOT SET');

    await mongoose.connect(MONGO_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000
    });

    isConnected = true;
    console.log(`✅ MongoDB conectado`);

    // Drop legacy non-sparse supportNumber index so mongoose can recreate it as sparse
    try {
      await mongoose.connection.db.collection('registros').dropIndex('supportNumber_1');
      console.log('Dropped old non-sparse supportNumber_1 index');
    } catch (e) {
      // Index did not exist or was already dropped, which is fine
    }

    await backfillSupportNumbers();
    await ensureBuiltinPendingMigrations();
    await ensureBuiltinSolicitantes();
  } catch (err) {
    console.error('❌ Error MongoDB:', err.message);
    console.error('   Code:', err.code);
    console.error('   Name:', err.name);
    throw err;
  }
}

// Middleware to ensure DB connection
app.use(async (req, res, next) => {
  try {
    await connectToDatabase();
    next();
  } catch (err) {
    res.status(500).json({ error: 'Database connection failed' });
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
          permitirWebFallback: item.permitirWebFallback
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
  const dbSolicitante = await Solicitante.findOne({ apiKey: key, activo: true });
  if (dbSolicitante) return dbSolicitante;
  return BUILTIN_SOLICITANTES.find(item => item.apiKey === key && item.activo) || null;
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
    const users = await Registro.find({
      $or: [
        { supportNumber: { $exists: false } },
        { supportNumber: null }
      ]
    });
    for (const user of users) {
      try {
        user.supportNumber = await generateUniqueSupportNumber();
        await user.save();
        console.log(`Backfilled support number ${user.supportNumber} for user ${user.nombre}`);
      } catch (saveErr) {
        console.error(`Error saving user ${user.nombre} during backfill:`, saveErr.message);
      }
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

    if (registro.twoFactorDisabled) {
      const loginPayload = {
        servicio: solicitante?.nombre || svc,
        servicioUrl,
        platform: platform || solicitante?.plataforma || 'web',
        state: oauthState || null
      };
      return res.json(await completeLogin(registro, loginPayload, req, 'completa_sin_2fa'));
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
app.post('/api/admin/ban', verifyToken, requireAdmin, async (req, res) => {
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

// ── API: PANEL JUNTA (ADMIN) ──────────────────────────────────────────────────

// Login de admin (misma pasarela pero devuelve token admin)
// El admin usa la pasarela normal.

// Listar registros
app.get('/api/admin/registros', verifyToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/desbloquear/:dip', verifyToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/toggle/:dip', verifyToken, requireAdmin, async (req, res) => {
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
app.get('/api/admin/logs', verifyToken, requireAdmin, async (req, res) => {
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
app.get('/api/admin/stats', verifyToken, requireAdmin, async (req, res) => {
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
app.post('/api/admin/solicitantes', verifyToken, requireAdmin, async (req, res) => {
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
    permitirWebFallback = true
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
      apiKey,
      creadoPor: req.user.registroId
    });
    res.status(201).json({ ok: true, solicitante, apiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Listar solicitantes
app.get('/api/admin/solicitantes', verifyToken, requireAdmin, async (req, res) => {
  try {
    const solicitantes = await Solicitante.find({}, '-apiKey').sort({ creadoEn: -1 });
    res.json(solicitantes);
  } catch (err) {
    res.status(500).json({ error: 'Error al obtener solicitantes' });
  }
});

// Obtener solicitante con apiKey (para admin)
app.get('/api/admin/solicitantes/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const solicitante = await Solicitante.findById(req.params.id);
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    res.json(solicitante); // Incluye apiKey
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Eliminar solicitante
app.delete('/api/admin/solicitantes/:id', verifyToken, requireAdmin, async (req, res) => {
  try {
    const solicitante = await Solicitante.findByIdAndDelete(req.params.id);
    if (!solicitante) return res.status(404).json({ error: 'Solicitante no encontrado' });
    res.json({ ok: true, mensaje: 'Solicitante eliminado' });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
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
      redirectUris: normalizeRedirectUris(solicitante.urlOrigen, solicitante.redirectUris),
      appScheme: solicitante.appScheme,
      packageName: solicitante.packageName,
      bundleId: solicitante.bundleId,
      deepLinkHost: solicitante.deepLinkHost,
      pkceRequired: solicitante.pkceRequired,
      permitirWebFallback: solicitante.permitirWebFallback
    });
  } catch (err) {
    res.status(500).json({ error: 'Error' });
  }
});

// Obtener instrucciones de implementación (admin)
app.get('/api/admin/solicitantes/:id/instrucciones', verifyToken, requireAdmin, async (req, res) => {
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
app.post('/api/mobil/register', async (req, res) => {
  try {
    const { dip, deviceToken, deviceName } = req.body;
    if (!dip || !deviceToken) return res.status(400).json({ error: 'DIP y deviceToken requeridos' });

    const cleanDip = normalizeDip(dip);
    const registro = await Registro.findOne({ dip: cleanDip });
    if (!registro) return res.status(404).json({ error: 'PlacetaID no encontrado' });
    if (registro.bloqueado || !registro.activo) return res.status(403).json({ error: 'PlacetaID bloqueado o inactivo' });

    // Check if deviceToken is already registered to another DIP
    const existingToken = await MobileDevice.findOne({ deviceToken, dip: { $ne: cleanDip } });
    if (existingToken) {
      await MobileDevice.deleteOne({ _id: existingToken._id });
    }

    // Check if this DIP already has a device registered
    const existingDevice = await MobileDevice.findOne({ dip: cleanDip });
    if (existingDevice) {
      existingDevice.deviceToken = deviceToken;
      existingDevice.deviceName = deviceName || 'Dispositivo móvil';
      existingDevice.activo = true;
      existingDevice.ultimoAcceso = new Date();
      await existingDevice.save();
      return res.json({ ok: true, mensaje: 'Dispositivo actualizado' });
    }

    await MobileDevice.create({
      dip: cleanDip,
      deviceToken,
      deviceName: deviceName || 'Dispositivo móvil',
      platform: 'android',
      activo: true
    });

    console.log(`📱 Dispositivo registrado para ${cleanDip}`);
    res.json({ ok: true, mensaje: 'Dispositivo registrado correctamente' });
  } catch (err) {
    console.error('Error register mobile:', err);
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Este DIP ya tiene un dispositivo registrado. Desvincula el anterior primero.' });
    }
    res.status(500).json({ error: 'Error al registrar dispositivo' });
  }
});

// Desvincular dispositivo
app.post('/api/mobil/unregister', async (req, res) => {
  try {
    const { dip } = req.body;
    if (!dip) return res.status(400).json({ error: 'DIP requerido' });

    const deleted = await MobileDevice.findOneAndDelete({ dip: normalizeDip(dip) });
    if (!deleted) return res.status(404).json({ error: 'No hay dispositivo registrado para este DIP' });

    console.log(`📱 Dispositivo desvinculado para ${dip}`);
    res.json({ ok: true, mensaje: 'Dispositivo desvinculado' });
  } catch (err) {
    res.status(500).json({ error: 'Error al desvincular dispositivo' });
  }
});

// Generar código de solicitud de autenticación (desde web)
app.post('/api/mobil/request', async (req, res) => {
  try {
    const { dip, servicio, servicioUrl, plataforma } = req.body;
    if (!dip || !servicio) return res.status(400).json({ error: 'DIP y servicio requeridos' });

    const cleanDip = normalizeDip(dip);
    const registro = await Registro.findOne({ dip: cleanDip });
    if (!registro) return res.status(404).json({ error: 'PlacetaID no encontrado' });
    if (registro.bloqueado || !registro.activo) return res.status(403).json({ error: 'Cuenta bloqueada o inactiva' });

    // Check device is registered
    const device = await MobileDevice.findOne({ dip: cleanDip, activo: true });
    if (!device) return res.status(404).json({ error: 'No hay dispositivo registrado para este PlacetaID. Usa 2FA.' });

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

// Obtener solicitudes pendientes para un dispositivo
app.get('/api/mobil/pending', async (req, res) => {
  try {
    const deviceToken = req.query.deviceToken;
    if (!deviceToken) return res.status(400).json({ error: 'deviceToken requerido' });

    const device = await MobileDevice.findOne({ deviceToken, activo: true });
    if (!device) return res.status(404).json({ error: 'Dispositivo no registrado' });

    const requests = await AuthRequest.find({
      dip: device.dip,
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
    const { requestId, dip, authorized, deviceToken } = req.body;
    if (!requestId || !dip) return res.status(400).json({ error: 'requestId y dip requeridos' });

    const cleanDip = normalizeDip(dip);

    // Verify device
    if (deviceToken) {
      const device = await MobileDevice.findOne({ deviceToken, dip: cleanDip, activo: true });
      if (!device) return res.status(403).json({ error: 'Dispositivo no autorizado para este DIP' });
    }

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

    if (deviceToken) {
      await MobileDevice.findOneAndUpdate(
        { deviceToken, dip: cleanDip },
        { ultimoAcceso: new Date() }
      );
    }

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
      metadatos: { tipo: 'placetaid_movil', codigo: authReq.codigo, requestId: authReq._id.toString() }
    });

    console.log(`📱 Solicitud ${authReq.codigo} ${authorized ? 'AUTORIZADA' : 'DENEGADA'} para ${cleanDip}`);

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

// ── SERVIR FRONTEND ───────────────────────────────────────────────────────────
app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'assets', 'faviid.png'));
});

// Catch-all for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── INICIAR SERVIDOR ──────────────────────────────────────────────────────────
// En desarrollo local, executar: npm start
if (require.main === module) {
  connectToDatabase()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
      });
    })
    .catch(err => {
      console.error('❌ Error conectando a MongoDB:', err);
    });
}

module.exports = app;
