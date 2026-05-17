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

---

## Primer uso — Crear administrador

1. Abre http://localhost:3000
2. Ve a **Configuración** (en el menú)
3. Pulsa **Crear administrador**
4. Escanea el QR con Google Authenticator o Authy
5. Guarda el secreto TOTP en un lugar seguro

Credenciales iniciales:
- DIP: `ADMIN-001`
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
Body: { dip, nombre, apellidos, fechaNacimiento, rol, password }
→ Devuelve: { dip, totpSecret, qrCode }

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
  "dip": "MBR-0042",
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
