require('dotenv').config();

const mongoose = require('mongoose');
const { MobileDevice, Registro } = require('../models');

const batchSize = 100;
const apiBase = String(process.env.PLACETAID_V27_API_URL || '').trim();
const deviceKey = String(process.env.PLACETAID_V27_DEVICE_KEY || '');
const apply = process.argv.includes('--apply');

function normalizeDip(value) {
  return String(value || '').replace(/[\s-]/g, '').toUpperCase();
}

function profileFrom(registro) {
  return {
    nombre: registro.nombre || registro.empresaNombre || '',
    apellidos: registro.apellidos || '',
    placeid: registro.placeid || '',
    correo: registro.correo || '',
    fechaNacimiento: registro.fechaNacimiento || null,
    rol: registro.rol || 'miembro',
    activo: registro.activo !== false,
    bloqueado: registro.bloqueado === true,
    banned: registro.banned === true,
  };
}

function deviceEntry(device, profile) {
  const dip = normalizeDip(device.dip);
  const deviceId = String(device.deviceId || device.deviceToken || '').trim();
  const platform = String(device.platform || device.tipo || '').toLowerCase();
  if (device.activo === false || !/^\d{8}[A-Z]$/.test(dip) ||
      deviceId.length < 16 || deviceId.length > 256 ||
      /[\u0000-\u001f]/.test(deviceId) || !profile) return null;
  return {
    dip,
    deviceId,
    deviceName: String(device.deviceName || (platform === 'pc' ? 'PC' : 'Dispositivo móvil')).slice(0, 100),
    method: ['pc', 'windows', 'mac', 'linux'].includes(platform) || device.tipo === 'pc' ? 'desktop' : 'mobile',
    profile: profileFrom(profile),
  };
}

function authenticatorEntry(registro) {
  const dip = normalizeDip(registro.dip);
  const secret = String(registro.totpSecret || '').replace(/=+$/g, '').toUpperCase();
  if (!/^\d{8}[A-Z]$/.test(dip) || !/^[A-Z2-7]{16,64}$/.test(secret) ||
      registro.totpVerified !== true || registro.twoFactorDisabled === true ||
      registro.activo === false || registro.bloqueado === true || registro.banned === true) return null;
  return { dip, secret, profile: profileFrom(registro) };
}

async function sendBatch(path, entries) {
  const endpoint = new URL(path, apiBase);
  const response = await fetch(endpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-PlacetaID-Device-Key': deviceKey,
    },
    body: JSON.stringify({ entries }),
    signal: AbortSignal.timeout(30_000),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || result.ok !== true) {
    throw new Error(`Authentication-method migration failed with HTTP ${response.status}`);
  }
  return result;
}

async function migrateDevices(applyChanges) {
  let scanned = 0;
  let eligible = 0;
  let rejected = 0;
  let skippedInactive = 0;
  let migrated = 0;
  let batch = [];
  const cursor = MobileDevice.find({
    dip: { $exists: true, $nin: [null, ''] },
  })
    .select('dip deviceId deviceToken deviceName platform tipo activo')
    .lean()
    .cursor();

  async function processBatch(devices) {
    const activeDevices = devices.filter((device) => device.activo !== false);
    const dips = [...new Set(activeDevices.map((device) => normalizeDip(device.dip)).filter((dip) => /^\d{8}[A-Z]$/.test(dip)))];
    const registrations = dips.length
        ? await Registro.find({ dip: { $in: dips } })
          .select('dip placeid nombre apellidos empresaNombre correo fechaNacimiento rol activo bloqueado banned')
        .lean()
        : [];
    const profiles = new Map(registrations.map((profile) => [normalizeDip(profile.dip), profile]));
    const entries = activeDevices.map((device) => deviceEntry(device, profiles.get(normalizeDip(device.dip))));
    const validEntries = entries.filter(Boolean);
    eligible += validEntries.length;
    rejected += entries.length - validEntries.length;
    skippedInactive += devices.filter((device) => device.activo === false).length;
    if (applyChanges && validEntries.length) {
      const result = await sendBatch('/api/internal/devices/migrate', validEntries);
      migrated += result.migrated || 0;
      skippedInactive += result.skippedInactive || 0;
    }
  }

  try {
    for await (const device of cursor) {
      scanned++;
      batch.push(device);
      if (batch.length >= batchSize) {
        await processBatch(batch);
        batch = [];
      }
    }
    if (batch.length) await processBatch(batch);
  } finally {
    await cursor.close();
  }
  return { scanned, eligible, rejected, skippedInactive, migrated };
}

async function migrateAuthenticators(applyChanges) {
  let scanned = 0;
  let eligible = 0;
  let rejected = 0;
  let skippedExisting = 0;
  let migrated = 0;
  let batch = [];
  const cursor = Registro.find({
    dip: { $exists: true, $nin: [null, ''] },
    totpSecret: { $type: 'string', $ne: '' },
    totpVerified: true,
    twoFactorDisabled: { $ne: true },
    activo: { $ne: false },
    bloqueado: { $ne: true },
    banned: { $ne: true },
  })
    .select('dip totpSecret totpVerified twoFactorDisabled nombre apellidos empresaNombre placeid correo fechaNacimiento rol activo bloqueado banned')
    .lean()
    .cursor();

  async function processBatch(registrations) {
    const entries = registrations.map(authenticatorEntry);
    const validEntries = entries.filter(Boolean);
    eligible += validEntries.length;
    rejected += entries.length - validEntries.length;
    if (applyChanges && validEntries.length) {
      const result = await sendBatch('/api/internal/authenticators/migrate', validEntries);
      migrated += result.migrated || 0;
      skippedExisting += result.skippedExisting || 0;
    }
  }

  try {
    for await (const registro of cursor) {
      scanned++;
      batch.push(registro);
      if (batch.length >= batchSize) {
        await processBatch(batch);
        batch = [];
      }
    }
    if (batch.length) await processBatch(batch);
  } finally {
    await cursor.close();
  }
  return { scanned, eligible, rejected, skippedExisting, migrated };
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  if (!apiBase || deviceKey.length < 32) throw new Error('PLACETAID_V27_API_URL and PLACETAID_V27_DEVICE_KEY are required');
  if (!apply) console.log('Dry run only. Add --apply to migrate active device and verified TOTP methods.');

  await mongoose.connect(process.env.MONGO_URI);
  const devices = await migrateDevices(apply);
  const authenticators = await migrateAuthenticators(apply);
  console.log(JSON.stringify({
    mode: apply ? 'applied' : 'dry-run',
    devices,
    authenticators,
    note: 'Only active device tokens and verified TOTP secrets are transferred over HTTPS; no passwords are read or sent.',
  }));
}

main()
  .catch((error) => {
    console.error(`[PlacetaID authentication-method migration] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
