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
const { Registro, Log, Solicitante } = require('./models');

const app = express();
const PORT = process.env.PORT || 3000;
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://malegre_db_user:gKHctbCg9KcYUrO8@cluster0.m5bntoj.mongodb.net/';
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const JWT_EXPIRY = '1h'; // Tokens de duración extendida para mejor usabilidad

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

function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  console.log('Auth header:', auth);
  if (!auth?.startsWith('Bearer ')) return res.status(401).json({ error: 'Token requerido' });
  const token = auth.slice(7);
  console.log('Token:', token);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    console.log('User:', req.user);
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
  return String(value || '').trim().toUpperCase().replace(/\s+/g, '-');
}

async function generateUniqueDip(prefix = 'DIP') {
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const candidate = `${prefix}-${crypto.randomInt(1000, 10000)}`;
    if (!(await Registro.exists({ dip: candidate }))) return candidate;
  }
  throw new Error('No se pudo generar DIP único');
}

async function createPlacetaIdRegistration(payload, context = {}) {
  const { dip, nombre, apellidos, fechaNacimiento, rol, password, empresaNombre, empresaCIF, propietarios } = payload;
  const cleanRol = rol || 'miembro';
  const cleanDip = normalizeDip(dip) || await generateUniqueDip(cleanRol === 'empresa' ? 'EMP' : 'DIP');

  if (!cleanDip || !nombre || !password) {
    const error = new Error('DIP, nombre y contraseña son requeridos');
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

  const existe = await Registro.findOne({ dip: cleanDip });
  if (existe) {
    const error = new Error('El DIP ya está registrado');
    error.statusCode = 409;
    throw error;
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const totp = speakeasy.generateSecret({ name: `PlacetaID:${cleanDip}`, issuer: 'Grupo de La Placeta', length: 20 });
  const registroData = {
    dip: cleanDip,
    nombre: String(nombre).trim(),
    rol: cleanRol,
    passwordHash,
    totpSecret: totp.base32,
    totpVerified: false
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
  await registrarLog({
    dip: registro.dip,
    registroId: registro._id,
    servicio: context.servicio || 'PlacetaID',
    servicioUrl: context.servicioUrl,
    evento: 'registro_creado',
    ip: context.ip,
    ua: context.ua,
    fase: 'completa',
    metadatos: context.metadatos
  });

  const qrUrl = await QRCode.toDataURL(totp.otpauth_url);
  return {
    ok: true,
    dip: registro.dip,
    nombre: registro.nombre,
    apellidos: registro.apellidos,
    nombreCompleto: registro.rol === 'empresa' ? registro.empresaNombre : `${registro.nombre} ${registro.apellidos}`.trim(),
    rol: registro.rol,
    totpSecret: totp.base32,
    qrCode: qrUrl,
    mensaje: 'Registro creado. Escanea el QR con tu autenticador y verifica el primer código.'
  };
}

// ── API: AUTENTICACIÓN ────────────────────────────────────────────────────────

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
      solicitante = await Solicitante.findOne({ apiKey: clientId, activo: true });
      if (!solicitante) return res.status(401).json({ error: 'Aplicación solicitante no autorizada' });
      const callbacks = normalizeRedirectUris(solicitante.urlOrigen, solicitante.redirectUris);
      if (servicioUrl && !isAllowedCallback(servicioUrl, callbacks)) {
        return res.status(400).json({ error: 'Callback no autorizado para esta aplicación' });
      }
    }

    const registro = await Registro.findOne({ dip: dip.toUpperCase() });

    if (!registro) {
      await registrarLog({ dip: dip.toUpperCase(), servicio: svc, servicioUrl, evento: 'error_credenciales', ip, ua, fase: 'fase1' });
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

    // AUTENTICACIÓN COMPLETA ✅
    registro.intentosFallidos = 0;
    registro.ultimoAcceso = new Date();
    await registro.save();

    await registrarLog({ dip: registro.dip, registroId: registro._id, servicio: payload.servicio, servicioUrl: payload.servicioUrl, evento: 'intento_exitoso', ip, ua, fase: 'completa' });

    // Token de sesión con datos del registro
    const tokenSesion = jwt.sign(
      { registroId: registro._id.toString(), dip: registro.dip, rol: registro.rol },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRY }
    );

    // Datos devueltos al servicio solicitante
    const datosRegistro = {
      dip: registro.dip,
      nombre: registro.nombre,
      apellidos: registro.apellidos,
      nombreCompleto: registro.rol === 'empresa' ? registro.empresaNombre : `${registro.nombre} ${registro.apellidos}`,
      edad: registro.edad,
      rol: registro.rol,
      accesoComo: registro.rol === 'empresa' ? 'empresa' : 'persona'
    };

    if (registro.rol === 'empresa') {
      datosRegistro.empresaNombre = registro.empresaNombre;
      datosRegistro.propietarios = registro.propietarios;
    }

    res.json({
      ok: true,
      tokenSesion,
      registro: datosRegistro,
      servicio: payload.servicio,
      plataforma: payload.platform || 'web',
      state: payload.state || null,
      expiresIn: 3600
    });

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
    const registro = await Registro.findOne({ dip: dip?.toUpperCase() });
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
    const registro = await Registro.findOne({ dip: req.params.dip.toUpperCase() });
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
    const registro = await Registro.findOne({ dip: req.params.dip.toUpperCase() });
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
    if (dip) filter.dip = dip.toUpperCase();
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
    const solicitante = await Solicitante.findOne({ apiKey: key, activo: true });
    if (!solicitante) return res.status(401).json({ error: 'API Key inválida o inactiva' });
    
    solicitante.ultimaUsaEn = new Date();
    await solicitante.save();
    
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
${solicitante.appScheme || 'bancoplaceta'}://${solicitante.deepLinkHost || 'auth/callback'}

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
app.post('/api/setup/seed-admin', async (req, res) => {
  try {
    console.log('🔧 POST /api/setup/seed-admin - Chequeando DB connection...');
    
    const existe = await Registro.findOne({ dip: 'ADMIN-001' });
    if (existe) {
      console.log('✓ Admin ya existe');
      return res.json({ ok: false, mensaje: 'El admin ya existe. DIP: ADMIN-001' });
    }

    const passwordHash = await bcrypt.hash('Admin1234!', 12);
    const totp = speakeasy.generateSecret({ name: 'PlacetaID:ADMIN-001', issuer: 'Grupo de La Placeta', length: 20 });
    const qrUrl = await QRCode.toDataURL(totp.otpauth_url);

    await Registro.create({
      dip: 'ADMIN-001', nombre: 'Administrador', apellidos: 'del Sistema',
      fechaNacimiento: new Date('1990-01-01'), rol: 'administrador',
      passwordHash, totpSecret: totp.base32, totpVerified: true
    });

    console.log('✓ Admin creado exitosamente');
    res.json({ ok: true, dip: 'ADMIN-001', password: 'Admin1234!', totpSecret: totp.base32, qrCode: qrUrl, mensaje: '⚠️ Admin creado. Guarda el secreto TOTP y elimina este endpoint en producción.' });
  } catch (err) {
    console.error('❌ Error en seed-admin:', err.message, err.code);
    res.status(500).json({ error: err.message, code: err.code });
  }
});

// ── SERVIR FRONTEND ───────────────────────────────────────────────────────────
app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

// Catch-all for SPA
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ── INICIAR SERVIDOR ──────────────────────────────────────────────────────────
// En desarrollo local, executar: npm start
if (require.main === module) {
  mongoose.connect(MONGO_URI)
    .then(() => {
      console.log('✅ Conectado a MongoDB');
      app.listen(PORT, () => {
        console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
      });
    })
    .catch(err => {
      console.error('❌ Error conectando a MongoDB:', err);
    });
}

module.exports = app;
