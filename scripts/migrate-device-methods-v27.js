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

function migrationDevice(device, profile) {
  const dip = normalizeDip(device.dip);
  const deviceId = String(device.deviceId || device.deviceToken || '').trim();
  const platform = String(device.platform || device.tipo || '').toLowerCase();
  if (!/^\d{8}[A-Z]$/.test(dip) || deviceId.length < 16 || deviceId.length > 256 ||
      /[\u0000-\u001f]/.test(deviceId) || !profile) return null;
  return {
    dip,
    deviceId,
    deviceName: String(device.deviceName || (platform === 'pc' ? 'PC' : 'Dispositivo móvil')).slice(0, 100),
    method: ['pc', 'windows', 'mac', 'linux'].includes(platform) || device.tipo === 'pc' ? 'desktop' : 'mobile',
    profile: {
      nombre: profile.nombre || '',
      apellidos: profile.apellidos || '',
      placeid: profile.placeid || '',
      correo: profile.correo || '',
      fechaNacimiento: profile.fechaNacimiento || null,
      rol: profile.rol || 'miembro',
      activo: profile.activo !== false,
      bloqueado: profile.bloqueado === true,
      banned: profile.banned === true,
    },
  };
}

async function migrateBatch(entries) {
  const endpoint = new URL('/api/internal/devices/migrate', apiBase);
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
    throw new Error(`Device migration failed with HTTP ${response.status}`);
  }
  return result;
}

async function prepareBatch(devices) {
  const dips = [...new Set(devices.map((device) => normalizeDip(device.dip)).filter((dip) => /^\d{8}[A-Z]$/.test(dip)))];
  const registrations = dips.length
    ? await Registro.find({ dip: { $in: dips } })
      .select('dip placeid nombre apellidos empresaNombre correo fechaNacimiento rol activo bloqueado banned')
      .lean()
    : [];
  const profiles = new Map(registrations.map((profile) => [normalizeDip(profile.dip), profile]));
  return devices.map((device) => migrationDevice(device, profiles.get(normalizeDip(device.dip))));
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  if (!apiBase || deviceKey.length < 32) throw new Error('PLACETAID_V27_API_URL and PLACETAID_V27_DEVICE_KEY are required');
  if (!apply) console.log('Dry run only. Add --apply to migrate active legacy mobile/Desktop methods.');

  await mongoose.connect(process.env.MONGO_URI);
  let scanned = 0;
  let eligible = 0;
  let skippedInactive = 0;
  let rejected = 0;
  let migrated = 0;
  let batch = [];

  const cursor = MobileDevice.find({
    dip: { $exists: true, $nin: [null, ''] },
    activo: { $ne: false },
  })
    .select('dip deviceId deviceToken deviceName platform tipo activo')
    .lean()
    .cursor();

  try {
    for await (const device of cursor) {
      scanned++;
      if (device.activo === false) {
        skippedInactive++;
        continue;
      }
      batch.push(device);
      if (batch.length < batchSize) continue;

      const entries = await prepareBatch(batch);
      const validEntries = entries.filter(Boolean);
      rejected += entries.length - validEntries.length;
      eligible += validEntries.length;
      if (apply && validEntries.length) {
        const result = await migrateBatch(validEntries);
        migrated += result.migrated || 0;
        skippedInactive += result.skippedInactive || 0;
      }
      batch = [];
    }
    if (batch.length) {
      const entries = await prepareBatch(batch);
      const validEntries = entries.filter(Boolean);
      rejected += entries.length - validEntries.length;
      eligible += validEntries.length;
      if (apply && validEntries.length) {
        const result = await migrateBatch(validEntries);
        migrated += result.migrated || 0;
        skippedInactive += result.skippedInactive || 0;
      }
    }
  } finally {
    await cursor.close();
  }

  console.log(JSON.stringify({
    mode: apply ? 'applied' : 'dry-run',
    scanned,
    eligible,
    rejected,
    skippedInactive,
    migrated,
    note: 'Only active device tokens are transferred over HTTPS; raw tokens and DIPs are not logged.',
  }));
}

main()
  .catch((error) => {
    console.error(`[PlacetaID device migration] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
