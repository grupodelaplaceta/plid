# 🔗 PlacetaID — Guía de Integración para Solicitantes

## Resumen

PlacetaID es una pasarela de autenticación centralizada. Los servicios externos (solicitantes) pueden redirigir a sus usuarios a PlacetaID para identificarse, y reciben un token JWT válido tras el login exitoso.

---

## Flujo de Autenticación

```
┌─────────────────┐          ┌──────────────────────┐          ┌──────────────┐
│  Tu Aplicación  │          │    PlacetaID Portal  │          │  Usuario     │
└────────┬────────┘          └──────────┬───────────┘          └──────┬───────┘
         │                              │                              │
         │ 1. Redirige con ?from=...    │                              │
         ├─────────────────────────────>│                              │
         │                              │ 2. Muestra formulario de     │
         │                              │    autenticación              │
         │                              │<─────────────────────────────│
         │                              │ 3. Usuario inicia sesión      │
         │                              │    (DIP + 2FA)                │
         │                              │─────────────────────────────>│
         │                              │ 4. Redirige con token        │
         │<─ token + user data ─────────┤<─────────────────────────────│
         │ 5. Establece sesión (cookie) │
         │
```

---

## Paso 1: Redirigir a PlacetaID

Cuando el usuario haga clic en "Iniciar sesión con PlacetaID", redirige a:

```javascript
const callbackUrl = encodeURIComponent('https://tu-app.com/auth/callback');
const placetaidUrl = `https://id.laplaceta.org/?from=${callbackUrl}`;
window.location.href = placetaidUrl;
```

**Parámetros:**
- `from` (requerido): URL donde PlacetaID debe redirigir después del login
  - Debe ser una URL HTTPS
  - Será la que reciba los parámetros de autenticación

---

## Paso 2: Recibir el token en tu Callback

PlacetaID redirigirá a tu URL de callback con dos parámetros:

```
https://tu-app.com/auth/callback?token=eyJhbGc...&user=%7B%22dip%22%3A...%7D
```

**Parámetros recibidos:**
- `token` (string): JWT válido para identificar futuras solicitudes a PlacetaID
  - Expira en 1 hora
  - Úsalo en el header `Authorization: Bearer {token}`
- `user` (JSON): Datos del usuario autenticado
  ```json
  {
    "dip": "12345678J",
    "nombre": "Juan",
    "apellidos": "Pérez",
    "nombreCompleto": "Juan Pérez",
    "edad": 35,
    "rol": "administrador"
  }
  ```

---

## Paso 3: Ejemplo de Implementación

### Frontend (JavaScript/HTML)

```javascript
// Botón de login
document.getElementById('loginBtn').addEventListener('click', () => {
  const callbackUrl = `${window.location.origin}/auth/callback`;
  window.location.href = `https://id.laplaceta.org/?from=${encodeURIComponent(callbackUrl)}`;
});

// En tu página de callback (auth/callback)
function handleCallback() {
  const params = new URLSearchParams(window.location.search);
  
  const token = params.get('token');
  const userStr = params.get('user');
  
  if (!token || !userStr) {
    console.error('No authentication data received');
    window.location.href = '/login';
    return;
  }
  
  const user = JSON.parse(decodeURIComponent(userStr));
  
  // Guardar token en cookie/sessionStorage
  localStorage.setItem('placetaidToken', token);
  localStorage.setItem('user', JSON.stringify(user));
  
  // Mostrar datos del usuario
  console.log('✅ Autenticado como:', user.nombreCompleto);
  
  // Redirigir al panel
  window.location.href = '/dashboard';
}

// Llamar al cargar
handleCallback();
```

### Backend (Node.js/Express)

```javascript
const express = require('express');
const jwt = require('jsonwebtoken');

app.get('/auth/callback', (req, res) => {
  const { token, user } = req.query;
  
  if (!token) {
    return res.status(400).send('No token provided');
  }
  
  // Verificar token en PlacetaID (opcional)
  // Tu backend puede validar el token haciendo una solicitud a PlacetaID
  
  // Guardar sesión
  req.session.token = token;
  req.session.user = JSON.parse(user);
  
  res.redirect('/dashboard');
});

// Middleware para proteger rutas
function requireAuth(req, res, next) {
  if (!req.session.token) {
    return res.status(401).send('Not authenticated');
  }
  next();
}

app.get('/dashboard', requireAuth, (req, res) => {
  res.send(`Bienvenido, ${req.session.user.nombreCompleto}`);
});
```

### Python (Flask)

```python
from flask import Flask, request, redirect, session
from urllib.parse import quote, unquote
import json

app = Flask(__name__)
app.secret_key = 'tu-clave-secreta'

PLACETAID_URL = 'https://id.laplaceta.org'
CALLBACK_URL = 'https://tu-app.com/auth/callback'

@app.route('/login')
def login():
    return redirect(f"{PLACETAID_URL}/?from={quote(CALLBACK_URL)}")

@app.route('/auth/callback')
def auth_callback():
    token = request.args.get('token')
    user_str = request.args.get('user')
    
    if not token:
        return 'Error: No token provided', 400
    
    user = json.loads(unquote(user_str))
    
    # Guardar en sesión
    session['token'] = token
    session['user'] = user
    
    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'token' not in session:
        return redirect('/login')
    
    user = session['user']
    return f"Bienvenido, {user['nombreCompleto']}"
```

---

## Paso 4: Usar el Token en Futuras Solicitudes

Una vez tienes el token, úsalo para identificarte ante PlacetaID en futuras solicitudes:

```javascript
// Solicitud a API que requiere autenticación
fetch('https://id.laplaceta.org/api/admin/solicitantes', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${localStorage.getItem('placetaidToken')}`,
    'Content-Type': 'application/json'
  }
})
.then(res => res.json())
.then(data => console.log(data));
```

---

## Seguridad

✅ **Recomendaciones:**

1. **Valida el origen**: Verifica que la solicitud venga de PlacetaID
2. **HTTPS obligatorio**: Siempre usa HTTPS en tu URL de callback
3. **Guarda el token de forma segura**: 
   - En el navegador: usar httpOnly cookies si es posible
   - En el servidor: guardar en base de datos encriptada
4. **Expira sesiones**: El token expira en 1 hora, pide nuevo login tras expirarlo
5. **CORS**: PlacetaID permite CORS; verifica headers `Origin`

---

## Endpoints Disponibles

### Obtener información del usuario autenticado

```
GET /api/admin/solicitantes
Authorization: Bearer {token}
Content-Type: application/json

Respuesta:
[
  {
    "nombre": "Mi Aplicación Web",
    "descripcion": "...",
    "urlOrigen": "https://mi-app.com",
    "apiKey": "...",
    "activo": true
  }
]
```

---

## Preguntas Frecuentes

**¿Qué sucede si el usuario cierra la sesión en PlacetaID?**
- El token sigue siendo válido hasta que expire (1 hora)
- Después de expirarlo, el usuario debe volver a autenticarse

**¿Puedo usar PlacetaID desde una aplicación móvil?**
- Sí, abre un navegador con `window.location.href` o componente WebView
- Recibe los parámetros en tu URL de callback configurada

**¿Qué pasa si hay error en la autenticación?**
- PlacetaID NO redirige — el usuario permanece en PlacetaID
- Implementar botón "Volver" en el formulario de login

**¿Puedo validar el token en mi backend?**
- Sí, decodifica el JWT y valida la firma usando la clave secreta compartida
- O haz solicitud a `/api/verify` (próximamente)

---

## Soporte

Para más información o issues:
- 📧 Email: admin@placeta.com
- 🐛 Issues: https://github.com/mial596/plid26/issues


