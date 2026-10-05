# PlacetaID — Pasarela de Identificación

Sistema de autenticación centralizado para el ecosistema Grupo de La Placeta.

## 🔗 Integración de Solicitantes

¿Quieres integrar PlacetaID en tu aplicación? Lee la **[Guía de Integración](./INTEGRACION_SOLICITANTES.md)**.

👉 [Ver ejemplo de funcionamiento](./public/ejemplo-integracion.html)

## Requisitos

- Node.js 18+
- MongoDB 6+ (local o remoto)

## Instalación

```bash
npm install
```

## Configuración

Edita el fichero `.env`:

```env
PORT=3000
MONGO_URI=mongodb://localhost:27017/placetaid
JWT_SECRET=tu-secreto-muy-largo-y-aleatorio
```

## Arrancar el servidor

```bash
node server.js
```

Accede en: http://localhost:3000

## Migrar cuentas antiguas a PlacetaID v27

La migración controlada conserva las contraseñas existentes verificando sus hashes bcrypt; no exporta ni transmite contraseñas en claro. Primero aplica las migraciones de Supabase `20261004` a `20261007` del repositorio `placetaid-web-2027` y configura `PLACETAID_V27_API_URL` y el mismo `PLACETAID_V27_DEVICE_KEY` de ambos servidores en `.env`.

Al registrar un dispositivo nuevo, PL26 verifica la contraseña antes de enlazar el perfil y el dispositivo con v27; no transfiere la contraseña. Para traer los métodos existentes en lote, configura `MONGO_URI`, `PLACETAID_V27_API_URL` y `PLACETAID_V27_DEVICE_KEY` en `.env`. Se migran dispositivos activos y autenticadores TOTP previamente verificados; se envían por HTTPS directamente al API interno v27, se almacenan los tokens como hashes y los secretos TOTP cifrados. No se transmiten contraseñas. Los dispositivos excluidos (inactivos o con datos inválidos) no se habilitan.

Primero revisa los conteos sin modificar nada:

```bash
npm run migrate:methods-v27
```

Para aplicar la migración idempotente:

```bash
npm run migrate:methods-v27 -- --apply
```

El informe muestra solo cantidades; nunca imprime DIPs, tokens ni secretos TOTP. Conserva `.env` fuera de Git. Las identidades deshabilitadas no reciben métodos activos.

Desde este directorio, ejecuta primero un informe de solo lectura:

```bash
npm run migrate:legacy-v27
```

Cuando el recuento sea el esperado, ejecuta la importación:

```bash
npm run migrate:legacy-v27 -- --apply
```

Se importan solo cuentas con DIP válido y hash bcrypt. Si su DIP todavía no existe en la tabla canónica `solicitantes`, se crea el perfil con los datos disponibles de MongoDB, preservando el estado bloqueado/inactivo. La importación es idempotente y no sobrescribe credenciales ya migradas. Después, el titular debe volver a vincular el móvil o Desktop para crear el método v27.

El script requiere acceso al MongoDB de PL26 (`MONGO_URI`) y conexión HTTPS al API v27. No subas los resultados, hashes ni variables de entorno a GitHub.

---

## Primer uso — Crear administrador

1. Abre http://localhost:3000
2. Ve a **Configuración** (en el menú)
3. Pulsa **Crear administrador**
4. Escanea el QR con Google Authenticator o Authy
5. Guarda el secreto TOTP en un lugar seguro

Credenciales iniciales:
- DIP: `00000000A`
- Contraseña: `Admin1234!`
- 2FA: código del autenticador

---

## API — Endpoints principales

### Autenticación (pasarela)

```
POST /api/auth/fase1
Body: { dip, password, servicio, servicioUrl }
→ Devuelve: { tokenFase2 }

POST /api/auth/fase2
Body: { tokenFase2, codigo2fa }
→ Devuelve: { tokenSesion, registro: { dip, nombre, apellidos, nombreCompleto, edad, rol, accesoComo, empresaNombre?, propietarios? } }
```

### Registro

```
POST /api/registro
Body: { dip, placeid, correo, nombre, apellidos, fechaNacimiento, rol, password }
→ Devuelve: { dip, placeid, correo, totpSecret, qrCode, otpauthUrl }

El DIP tiene formato DNI: 8 dígitos y una letra final. La letra debe ser la inicial del nombre. Si no se envía, PLID26 lo genera automáticamente.
`placeid` y `correo` se guardan en la misma colección MongoDB del registro para poder recuperar el QR de Authenticator.

Para empresas:
```
POST /api/registro
Body: {
  dip,
  nombre,
  rol: 'empresa',
  password,
  empresaNombre,
  empresaCIF?,
  propietarios: [
    { nombre, apellidos?, placetaId, porcentaje }
  ]
}
→ Devuelve: { dip, totpSecret, qrCode }
```

POST /api/registro/verificar-totp
Body: { dip, codigo }
```

```
POST /api/registro/recuperar-authenticator
Body: { dip, correo? }
→ Devuelve: { dip, placeid, correo, totpSecret, qrCode, otpauthUrl }

Si el DIP esta en migraciones pendientes, devuelve `migration_requires_registration`: GDLP debe completar un alta normal con ese DIP ya asignado antes de generar el QR.
```

```
POST /api/migraciones/pendientes
Headers: { x-migration-key? }
Body: { dip, placeid?, placeidAnterior?, nombre?, apellidos?, correo?, origen? }
Body lote: { registros: [ ... ] }
→ Guarda DIPs/PlacetaID antiguos en la lista independiente de migraciones pendientes.
```

```
GET /api/migraciones/pendientes/:dip
→ Devuelve: { dip, placeid, estado }

GDLP usa esta consulta para bloquear el DIP/PlacetaID asignado y pedir despues los datos completos del usuario como un alta normal.
```

### Panel Junta (requiere token admin)

```
GET  /api/admin/stats
GET  /api/admin/registros
GET  /api/admin/logs?dip=&evento=&limit=&page=
POST /api/admin/desbloquear/:dip
POST /api/admin/toggle/:dip
```

---

## Respuesta de la pasarela

Tras autenticación exitosa, PlacetaID devuelve al servicio solicitante:

```json
{
  "dip": "12345678J",
  "nombre": "Juan",
  "apellidos": "García López",
  "nombreCompleto": "Juan García López",
  "edad": 28,
  "rol": "miembro"
}
```

---

## Política de seguridad

- **3 intentos fallidos** → bloqueo automático de cuenta
- Desbloqueo solo mediante la Junta (`POST /api/admin/desbloquear/:dip`)
- Tokens JWT de sesión con expiración de 15 minutos
- Contraseñas hasheadas con bcrypt (coste 12)
- 2FA mediante TOTP (RFC 6238, compatible con Google Authenticator / Authy)
- Rate limiting en endpoints de autenticación
- Logs completos de toda la actividad de autenticación

---

## Roles disponibles

| Rol | Descripción |
|-----|-------------|
| `administrador` | Acceso total al panel de la Junta |
| `moderador` | Moderación del ecosistema |
| `miembro` | Registro estándar |
| `entidad` | Organización/entidad del ecosistema |
| `visitante` | Acceso limitado |
