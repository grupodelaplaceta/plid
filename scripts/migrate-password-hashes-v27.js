require('dotenv').config();

const mongoose = require('mongoose');
const { Registro } = require('../models');

const batchSize = 100;
const apiBase = String(process.env.PLACETAID_V27_API_URL || '').trim();
const deviceKey = String(process.env.PLACETAID_V27_DEVICE_KEY || '');
const apply = process.argv.includes('--apply');

function ageFrom(dateValue) {
  if (!dateValue) return null;
  const birth = new Date(dateValue);
  if (Number.isNaN(birth.getTime())) return null;
  const today = new Date();
  return today.getFullYear() - birth.getFullYear()
    - (today.getMonth() < birth.getMonth() || (today.getMonth() === birth.getMonth() && today.getDate() < birth.getDate()) ? 1 : 0);
}

function migrationEntry(registro) {
  const dip = String(registro.dip || '').replace(/[\s-]/g, '').toUpperCase();
  const passwordHash = String(registro.passwordHash || '');
  if (!/^\d{8}[A-Z]$/.test(dip) || !/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(passwordHash)) return null;
  const nombre = [registro.nombre, registro.apellidos].filter(Boolean).join(' ').trim()
    || registro.empresaNombre
    || registro.placeid
    || '';
  return {
    dip,
    passwordHash,
    profile: {
      nombre,
      placeid: registro.placeid || '',
      correo: registro.correo || '',
      fechaNacimiento: registro.fechaNacimiento || null,
      edad: ageFrom(registro.fechaNacimiento),
      rol: registro.rol || 'miembro',
      activo: registro.activo !== false,
      bloqueado: registro.bloqueado === true,
      banned: registro.banned === true,
    },
  };
}

async function importBatch(entries) {
  const endpoint = new URL('/api/internal/legacy/credentials/import', apiBase);
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
    throw new Error(`Credential import failed with HTTP ${response.status}`);
  }
  return result;
}

async function main() {
  if (!process.env.MONGO_URI) throw new Error('MONGO_URI is required');
  if (!apiBase || deviceKey.length < 32) throw new Error('PLACETAID_V27_API_URL and PLACETAID_V27_DEVICE_KEY are required');
  if (!apply) console.log('Dry run only. Add --apply to transfer bcrypt hashes and legacy identity fields to v27.');

  await mongoose.connect(process.env.MONGO_URI);
  let scanned = 0;
  let eligible = 0;
  let rejected = 0;
  let imported = 0;
  let identitiesCreated = 0;
  let batch = [];

  const cursor = Registro.find({
    dip: { $exists: true, $nin: [null, ''] },
    passwordHash: { $type: 'string', $ne: '' },
  })
    .select('dip placeid nombre apellidos empresaNombre correo fechaNacimiento rol activo bloqueado banned passwordHash')
    .lean()
    .cursor();

  try {
    for await (const registro of cursor) {
      scanned += 1;
      const entry = migrationEntry(registro);
      if (!entry) {
        rejected += 1;
        continue;
      }
      eligible += 1;
      batch.push(entry);
      if (batch.length >= batchSize) {
        if (apply) {
          const result = await importBatch(batch);
          imported += result.imported || 0;
          identitiesCreated += result.identitiesCreated || 0;
        }
        batch = [];
      }
    }
    if (batch.length && apply) {
      const result = await importBatch(batch);
      imported += result.imported || 0;
      identitiesCreated += result.identitiesCreated || 0;
    }
  } finally {
    await cursor.close();
  }

  console.log(JSON.stringify({
    mode: apply ? 'applied' : 'dry-run',
    scanned,
    eligible,
    rejected,
    imported,
    identitiesCreated,
    note: 'Only bcrypt hashes are transferred; plaintext passwords are never read or sent.',
  }));
}

main()
  .catch((error) => {
    console.error(`[PlacetaID migration] ${error.message}`);
    process.exitCode = 1;
  })
  .finally(async () => {
    await mongoose.disconnect();
  });
