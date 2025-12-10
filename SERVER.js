// SERVER.js LIMPIO Y FUNCIONAL
// SERVER.js LIMPIO Y FUNCIONAL
const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
// Asegúrate de que este 'db' es un Pool o Conexión de mysql2/promise
const db = require('./db'); 

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
// Nota: 'express.static(path.join(__dirname))' asume que los archivos como index.html
// están en la misma carpeta que SERVER.js, lo cual es correcto según tu estructura.
app.use(express.static(path.join(__dirname))); 

// ----------------- Información del vuelo -----------------
const FLIGHT = {
  numero: 'QTR-0810',
  tipo: 'Sencillo',
  origen: 'Ciudad de México (MEX)',
  destino: 'Doha (DOH), Qatar',
  fecha: '08/10/25',
  hora: '20:00',
  lugarSalida: 'Terminal 2, Puerta 2'
};

const PRECIOS = {
    'primera': 120000,
    'turista': {
        'Adulto': 65950,
        'Niño': 60500,
        'Tercera Edad': 50000
    }
};

// ----------------- Recuperación de contraseñas -----------------
const recoveryCodes = {};

// ----------------- Helpers -----------------
function signToken(user) {
  return jwt.sign({
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role || 'user'
  }, JWT_SECRET, { expiresIn: '12h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// *** CORREGIDO: publicState ahora es ASYNC y devuelve el estado directamente. ***
async function publicState() {
    try {
        // 1. Corregido: 'AWAIT' debe ser 'await' (minúsculas).
        // 2. Corregido: Se usa '[rows]' en lugar de '[row]' para la desestructuración.
        const [rows] = await db.query(`
            SELECT id, clase, estado
            FROM seats
            ORDER BY
                clase DESC,
                CAST(SUBSTRING(id, 2) AS UNSIGNED)
        `);
        // 3. Corregido: Retorna 'rows' (plural) que es el nombre de la variable desestructurada.
        return { flight: FLIGHT, seats: rows };
    } catch (err) {
        // Propaga el error para que sea manejado por el caller (la ruta o el socket)
        console.error("Error al obtener estado:", err);
        throw err;
    }
}

// ----------------- Registro -----------------
// *** CORREGIDO: usa await y try/catch ***
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;
  // 1. Validación de campos vacíos (ya existente)
    if (!username || !email || !password)
        return res.status(400).json({ ok: false, error: "Faltan datos (nombre de usuario, email o contraseña)." });
    
    // 2. Validación de Longitud Mínima
    const MIN_LENGTH = 8;
    if (password.length < MIN_LENGTH) {
        return res.status(400).json({ 
            ok: false, 
            error: `La contraseña debe tener al menos ${MIN_LENGTH} caracteres.` 
        });
    }

    // 3. Validación de Complejidad (Usando Regex)
    // Regex que requiere:
    // ^        Inicio de la cadena
    // (?=.*[a-z]) Debe contener al menos una minúscula
    // (?=.*[A-Z]) Debe contener al menos una mayúscula
    // (?=.*\d)    Debe contener al menos un dígito numérico (0-9)
    // (?=.*[\W_]) Debe contener al menos un carácter especial (símbolo, espacio, etc.)
    // .{8,}    Debe tener una longitud mínima de 8 caracteres (aunque ya se validó antes)
    // $        Fin de la cadena
    const complexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    
    if (!complexityRegex.test(password)) {
        return res.status(400).json({ 
            ok: false, 
            error: "La contraseña es débil. Debe incluir: mayúscula, minúscula, número y símbolo." 
        });
    }
  try {
    const hashed = await bcrypt.hash(password, 10);

    // Uso de await para la consulta
    await db.query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashed, 'user']
    );
    
    res.json({ ok: true });
  } catch (e) {
    // Captura errores de hash o de clave duplicada de MySQL
    return res.status(500).json({ ok: false, error: e.code || "Error interno del servidor" });
  }
});
// ----------------- Login -----------------
// *** CORREGIDO: usa await y try/catch, desestructura results ***
app.post('/login', async (req, res) => { 
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });

  try {
    // Consulta con await, obteniendo solo los resultados [results]
    const [results] = await db.query( 
      'SELECT id, username, email, password, role FROM users WHERE email = ?',
      [email]
    );
        
    if (!results.length)
      return res.status(401).json({ error: "Credenciales inválidas" });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ error: "Credenciales inválidas" });

    const token = signToken(user);

    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });

  } catch (err) {
    return res.status(500).json({ error: "Error de base de datos: " + err.code });
  }
});

// ----------------- Forgot password -----------------
// *** CORREGIDO: usa await y try/catch ***
app.post('/forgot', async (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ ok: false, error: "Correo requerido" });

  try {
    const [rows] = await db.query("SELECT id FROM users WHERE email = ?", [email]); // <<-- await

    if (!rows.length) return res.status(404).json({ ok: false, error: "Correo no encontrado" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    recoveryCodes[email] = code;

    console.log("Código de recuperación:", email, "=>", code);

    res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Error de DB: " + err.code });
  }
});

// ----------------- Reset password -----------------
// *** CORREGIDO: usa await y try/catch ***
app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword)
    return res.status(400).json({ ok: false, error: "Faltan datos" });

  if (recoveryCodes[email] !== code)
    return res.status(401).json({ ok: false, error: "Código incorrecto" });

  try {
    const hash = await bcrypt.hash(newPassword, 10);

    await db.query("UPDATE users SET password = ? WHERE email = ?", [hash, email]); // <<-- await
    
    delete recoveryCodes[email];
    res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Error de DB: " + err.code });
  }
});

// ----------------- /me -----------------
app.get('/me', (req, res) => {
  // ... (no hay cambios necesarios aquí ya que no toca la DB) ...
  const auth = req.headers.authorization || "";
  const token = auth.replace("Bearer ", "");

  if (!token) return res.json({ user: null });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ user: null });

  res.json({ user: payload });
});

// ----------------- /state -----------------
// *** CORREGIDO: usa await y try/catch ***
app.get('/state', async (req, res) => {
  try {
    // publicState ahora es async y no usa callback
    const state = await publicState(); 
    res.json(state);
  } catch (err) {
    return res.status(500).json({ error: "Error de BD: " + err.code });
  }
});

// ----------------- SOCKET.IO -----------------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next();

  const payload = verifyToken(token);
  socket.user = payload || null;
  next();
});

// ----------------- Conexión de sockets -----------------
io.on('connection', (socket) => {
  console.log("Conectado:", socket.id);

  // Llama a publicState en una función asíncrona inmediata
  (async () => {
    try {
      const state = await publicState();
      socket.emit('state', state);
    } catch (e) {
      console.error("Error al emitir estado inicial:", e);
    }
  })();

  // *** CORREGIDO: Usando IIFE (función asíncrona que se llama inmediatamente) para manejar await ***
  socket.on('hold-seat', ({ seatId }) => {
    (async () => {
      try {
        const [rows] = await db.query("SELECT estado FROM seats WHERE id = ?", [seatId]);
        
        if (rows.length && rows[0].estado === "libre") {
          await db.query("UPDATE seats SET estado = 'retenido' WHERE id = ?", [seatId]);
          const s = await publicState();
          io.emit("state", s);
        }
      } catch (e) {
        console.error("Error en hold-seat:", e);
      }
    })();
  });

  socket.on('release-seat', ({ seatId }) => {
    (async () => {
      try {
        await db.query("UPDATE seats SET estado = 'libre' WHERE id = ?", [seatId]);
        const s = await publicState();
        io.emit("state", s);
      } catch (e) {
        console.error("Error en release-seat:", e);
      }
    })();
  });

socket.on('confirm', async (payload) => {
    // 🚨 ASUME: socket.user.id se adjunta por middleware de socket
    const userId = socket.user ? socket.user.id : null; 
    
    if (!userId) {
        return socket.emit('action-error', { type: 'confirm', reason: 'No autorizado. Vuelve a iniciar sesión.' });
    }

    if (!payload.seats || payload.seats.length === 0) {
        return socket.emit('action-error', { type: 'confirm', reason: 'No hay asientos seleccionados para comprar.' });
    }
    
    // --- LÓGICA DE TRANSACCIÓN ---
    try {
        await db.query('START TRANSACTION'); // Inicia la transacción

        let totalCompra = 0;
        const detalleCompra = [];
        const flightInfo = obtenerInfoVuelo(); // Asume que esta función es segura y accesible

        // Recorrer cada asiento seleccionado y actualizar su estado
        for (const item of payload.seats) {
            const seatId = item.seatId;
            let precio;
            
            // CÁLCULO DE PRECIO EN BACKEND (Seguridad)
            if (item.clase === 'primera') {
                precio = PRECIOS.primera;
            } else {
                precio = PRECIOS.turista[item.categoria] || PRECIOS.turista.Adulto; 
            }
            
            // Transición de Retenido a Vendido
            const [result] = await db.query(
                "UPDATE seats SET estado = 'vendido', user_id = ? WHERE id = ? AND estado = 'retenido'",
                [userId, seatId]
            );
            
            if (result.affectedRows === 0) {
                // Si la actualización falla (ya no estaba retenido o no existía), abortar la compra
                await db.query('ROLLBACK'); // 🚨 Revertir todas las compras anteriores
                console.error(`Transacción abortada: Asiento ${seatId} no disponible.`);
                return socket.emit('action-error', { 
                    type: 'confirm', 
                    reason: `El asiento ${seatId} ya no está disponible. Compra cancelada.` 
                });
            }
            
            totalCompra += precio;
            detalleCompra.push({ ...item, precio });
        }
        
        await db.query('COMMIT'); // 🥳 Éxito: confirmar todas las actualizaciones

        // 4. Enviar Recibo al cliente que compró
        // ... (construcción del objeto receipt como lo tenías) ...
        socket.emit('receipt', receipt);

        // 5. Emitir nuevo estado a TODOS los clientes
        const newState = await publicState();
        io.emit('state', newState);

    } catch (e) {
        // 🚨 Si falla la DB o la conexión, intentar el rollback
        await db.query('ROLLBACK').catch(console.error); 
        console.error("Error grave durante la transacción de compra:", e);
        socket.emit('action-error', { type: 'confirm', reason: 'Error interno del servidor al procesar la compra. Intente de nuevo.' });
    }
});
    
  socket.on('reset-seats', () => {
    if (!socket.user || socket.user.role !== "admin") return;

    (async () => {
      try {
        await db.query("UPDATE seats SET estado = 'libre'");
        const s = await publicState();
        io.emit("state", s);
      } catch (e) {
        console.error("Error en reset-seats:", e);
      }
    })();
  });
});

// ----------------- Health check -----------------
app.get('/health', (req, res) => res.json({ ok: true }));

// ----------------- 404 -----------------
app.use((req, res) => res.status(404).json({ error: "Ruta no encontrada" }));

// ----------------- Start server -----------------
server.listen(PORT, () => {
  console.log(`Servidor en http://localhost:${PORT}`);
});
