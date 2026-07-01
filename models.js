const mongoose = require('mongoose');

// ── REGISTRO (Usuario) ────────────────────────────────────────────────────────
const registroSchema = new mongoose.Schema({
  dip: {
    type: String,
    required: false,
    unique: true,
    sparse: true,
    uppercase: true,
    trim: true,
    match: /^\d{8}[A-Z]$/
  },
  placeid: {
    type: String,
    trim: true,
    uppercase: true,
    index: true
  },
  correo: {
    type: String,
    trim: true,
    lowercase: true,
    index: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  nombre: { type: String, required: true, trim: true },
  apellidos: {
    type: String,
    trim: true,
    required: function () { return this.rol !== 'empresa' && this.dip; }
  },
  fechaNacimiento: {
    type: Date,
    required: function () { return this.rol !== 'empresa' && this.dip; }
  },
  empresaNombre: {
    type: String,
    trim: true,
    required: function () { return this.rol === 'empresa'; }
  },
  empresaCIF: {
    type: String,
    trim: true,
    uppercase: true
  },
  rol: {
    type: String,
    enum: ['administrador', 'miembro', 'entidad', 'visitante', 'moderador', 'empresa'],
    default: 'miembro'
  },
  passwordHash: { type: String, required: false },
  totpSecret: { type: String, required: false },
  totpVerified: { type: Boolean, default: false },
  twoFactorDisabled: { type: Boolean, default: false },
  migradoDesdePendiente: { type: Boolean, default: false },
  bloqueado: { type: Boolean, default: false },
  intentosFallidos: { type: Number, default: 0 },
  ultimoBloqueo: { type: Date },
  activo: { type: Boolean, default: true },
  creadoEn: { type: Date, default: Date.now },
  ultimoAcceso: { type: Date },
  supportNumber: {
    type: String,
    required: false,
    unique: true,
    sparse: true,
    match: /^\d{8}$/
  },
  points: {
    type: Number,
    default: 0
  },
  banned: {
    type: Boolean,
    default: false
  },
  bannedUntil: {
    type: Date,
    default: null
  },
  socialLoginType: {
    type: String,
    trim: true
  },
  socialLoginId: {
    type: String,
    trim: true,
    index: true
  },
  ultimoAcceso: { type: Date },
  propietarios: {
    type: [
      {
        nombre: { type: String, required: true, trim: true },
        apellidos: { type: String, trim: true },
        placetaId: { type: String, required: true, uppercase: true, trim: true },
        porcentaje: { type: Number, min: 0, max: 100, required: true }
      }
    ],
    validate: [
      {
        validator: function (v) {
          if (this.rol !== 'empresa') return true;
          return Array.isArray(v) && v.length > 0;
        },
        message: 'Las empresas deben tener al menos un propietario con porcentaje'
      },
      {
        validator: function (v) {
          if (this.rol !== 'empresa') return true;
          return Array.isArray(v) && v.every(p => p.placetaId && typeof p.porcentaje === 'number');
        },
        message: 'Cada propietario debe tener placetaId y porcentaje'
      }
    ]
  }
});

// Calcular edad dinámica
registroSchema.virtual('edad').get(function () {
  if (!this.fechaNacimiento) return null;
  const hoy = new Date();
  const nac = new Date(this.fechaNacimiento);
  let edad = hoy.getFullYear() - nac.getFullYear();
  const m = hoy.getMonth() - nac.getMonth();
  if (m < 0 || (m === 0 && hoy.getDate() < nac.getDate())) edad--;
  return edad;
});

registroSchema.set('toJSON', { virtuals: true });

// ── LOG DE AUTENTICACIÓN ──────────────────────────────────────────────────────
const logSchema = new mongoose.Schema({
  dip: { type: String },
  registroId: { type: mongoose.Schema.Types.ObjectId, ref: 'Registro' },
  servicio: { type: String, required: true },      // web/servicio que solicitó acceso
  servicioUrl: { type: String },
  evento: {
    type: String,
    enum: [
      'intento_exitoso',
      'error_credenciales',
      'error_2fa',
      'cuenta_bloqueada',
      'bloqueo_activado',
      'desbloqueo',
      'registro_creado',
      'totp_configurado',
      'totp_recuperado'
    ],
    required: true
  },
  ip: { type: String },
  userAgent: { type: String },
  fase: { type: String, enum: ['fase1', 'fase2', 'completa'] },
  intentoNumero: { type: Number },
  metadatos: { type: mongoose.Schema.Types.Mixed },
  timestamp: { type: Date, default: Date.now }
});

logSchema.index({ dip: 1, timestamp: -1 });
logSchema.index({ timestamp: -1 });

// ── SOLICITANTE (Aplicación/Servicio) ─────────────────────────────────────────
const solicitanteSchema = new mongoose.Schema({
  nombre: { type: String, required: true, trim: true },
  descripcion: { type: String, trim: true },
  plataforma: {
    type: String,
    enum: ['web', 'android', 'ios', 'desktop', 'backend', 'multiplataforma'],
    default: 'web'
  },
  urlOrigen: { type: String, required: true, trim: true }, // Callback principal heredado
  redirectUris: [{ type: String, trim: true }],
  appScheme: { type: String, trim: true },
  packageName: { type: String, trim: true },
  bundleId: { type: String, trim: true },
  deepLinkHost: { type: String, trim: true },
  pkceRequired: { type: Boolean, default: true },
  permitirWebFallback: { type: Boolean, default: true },
  apiKey: { type: String, required: true, unique: true }, // Clave única para validar
  logo: { type: String, trim: true, default: '' },        // URL o data URI del logo
  bgColor: { type: String, trim: true, default: '' },     // Color de fondo hex (#1c005f)
  activo: { type: Boolean, default: true },
  creadoPor: { type: mongoose.Schema.Types.ObjectId, ref: 'Registro' }, // Admin que lo creó
  creadoEn: { type: Date, default: Date.now },
  ultimaUsaEn: { type: Date }
});

solicitanteSchema.index({ urlOrigen: 1 });
solicitanteSchema.index({ plataforma: 1, activo: 1 });

// ── MIGRACIONES PENDIENTES ───────────────────────────────────────────────────
const migracionPendienteSchema = new mongoose.Schema({
  dip: {
    type: String,
    required: true,
    unique: true,
    uppercase: true,
    trim: true,
    match: /^\d{8}[A-Z]$/
  },
  placeidAnterior: { type: String, trim: true, uppercase: true },
  placeid: { type: String, required: true, trim: true, uppercase: true, index: true },
  nombre: { type: String, trim: true, default: 'Miembro' },
  apellidos: { type: String, trim: true, default: 'GDLP' },
  correo: {
    type: String,
    trim: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  estado: {
    type: String,
    enum: ['pendiente', 'migrado', 'cancelado'],
    default: 'pendiente',
    index: true
  },
  origen: { type: String, trim: true, default: 'migracion_gdlp' },
  registroId: { type: mongoose.Schema.Types.ObjectId, ref: 'Registro' },
  creadoEn: { type: Date, default: Date.now },
  migradoEn: { type: Date }
});

// ── DISPOSITIVO MÓVIL (PlacetaID Móvil) ──────────────────────────────────────
const mobileDeviceSchema = new mongoose.Schema({
  dip: {
    type: String,
    required: true,
    uppercase: true,
    trim: true,
    match: /^\d{8}[A-Z]$/,
    unique: true // Solo un dispositivo por PlacetaID
  },
  deviceToken: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },
  deviceName: {
    type: String,
    trim: true,
    default: 'Dispositivo móvil'
  },
  platform: {
    type: String,
    enum: ['android', 'ios'],
    default: 'android'
  },
  activo: { type: Boolean, default: true },
  ultimoAcceso: { type: Date },
  registradoEn: { type: Date, default: Date.now }
});

mobileDeviceSchema.index({ deviceToken: 1 });

// ── SOLICITUD DE AUTENTICACIÓN (PlacetaID Móvil) ─────────────────────────────
const authRequestSchema = new mongoose.Schema({
  codigo: {
    type: String,
    required: true,
    uppercase: true,
    trim: true,
    match: /^[A-Z0-9]{4,8}$/
  },
  dip: {
    type: String,
    required: true,
    uppercase: true,
    trim: true,
    match: /^\d{8}[A-Z]$/
  },
  servicio: { type: String, required: true, trim: true },
  servicioUrl: { type: String, trim: true },
  plataforma: { type: String, default: 'web' },
  estado: {
    type: String,
    enum: ['pending', 'authorized', 'denied', 'expired'],
    default: 'pending',
    index: true
  },
  autorizadoEn: { type: Date },
  expiraEn: { type: Date, default: () => new Date(Date.now() + 5 * 60 * 1000) }, // 5 min
  creadoEn: { type: Date, default: Date.now }
});

authRequestSchema.index({ codigo: 1 });
authRequestSchema.index({ dip: 1, estado: 1 });
authRequestSchema.index({ expiraEn: 1 }, { expireAfterSeconds: 0 }); // TTL: borrar expirados

const Registro = mongoose.model('Registro', registroSchema);
const Log = mongoose.model('Log', logSchema);
const Solicitante = mongoose.model('Solicitante', solicitanteSchema);
const MigracionPendiente = mongoose.model('MigracionPendiente', migracionPendienteSchema);
const MobileDevice = mongoose.model('MobileDevice', mobileDeviceSchema);
const AuthRequest = mongoose.model('AuthRequest', authRequestSchema);

module.exports = { Registro, Log, Solicitante, MigracionPendiente, MobileDevice, AuthRequest };
