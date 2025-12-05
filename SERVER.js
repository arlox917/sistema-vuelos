// SERVER.js LIMPIO Y FUNCIONAL
const express = require('express');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3000;

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(express.json());
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

function publicState(cb) {
  db.query(`
    SELECT id, clase, estado 
    FROM seats 
    ORDER BY 
      clase DESC,
      CAST(SUBSTRING(id, 2) AS UNSIGNED)
  `, (err, rows) => {
    if (err) return cb(err);
    cb(null, { flight: FLIGHT, seats: rows });
  });
}

// ----------------- Registro -----------------
app.post('/register', async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password)
    return res.status(400).json({ ok: false, error: "Faltan datos" });

  try {
    const hashed = await bcrypt.hash(password, 10);

    db.query(
      'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
      [username, email, hashed, 'user'],
      err => {
        if (err) return res.status(500).json({ ok: false, error: err.code });
        res.json({ ok: true });
      }
    );
  } catch (e) {
    return res.status(500).json({ ok: false, error: "Error interno" });
  }
});

// ----------------- Login -----------------
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ error: "Usuario y contraseña requeridos" });

  db.query(
    'SELECT id, username, email, password, role FROM users WHERE email = ?',
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Error de base de datos" });

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
    }
  );
});

// ----------------- Forgot password -----------------
app.post('/forgot', (req, res) => {
  const { email } = req.body;

  if (!email)
    return res.status(400).json({ ok: false, error: "Correo requerido" });

  db.query("SELECT id FROM users WHERE email = ?", [email], (err, rows) => {
    if (err) return res.status(500).json({ ok: false, error: "Error de DB" });
    if (!rows.length) return res.status(404).json({ ok: false, error: "Correo no encontrado" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    recoveryCodes[email] = code;

    console.log("Código de recuperación:", email, "=>", code);

    res.json({ ok: true });
  });
});

// ----------------- Reset password -----------------
app.post('/reset-password', async (req, res) => {
  const { email, code, newPassword } = req.body;

  if (!email || !code || !newPassword)
    return res.status(400).json({ ok: false, error: "Faltan datos" });

  if (recoveryCodes[email] !== code)
    return res.status(401).json({ ok: false, error: "Código incorrecto" });

  const hash = await bcrypt.hash(newPassword, 10);

  db.query("UPDATE users SET password = ? WHERE email = ?", [hash, email], err => {
    if (err) return res.status(500).json({ ok: false, error: "Error de DB" });

    delete recoveryCodes[email];
    res.json({ ok: true });
  });
});

// ----------------- /me -----------------
app.get('/me', (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace("Bearer ", "");

  if (!token) return res.json({ user: null });

  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ user: null });

  res.json({ user: payload });
});

// ----------------- /state -----------------
app.get('/state', (req, res) => {
  publicState((err, state) => {
    if (err) return res.status(500).json({ error: "Error de BD" });
    res.json(state);
  });
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

  publicState((err, state) => {
    if (!err) socket.emit('state', state);
  });

  socket.on('hold-seat', ({ seatId }) => {
    db.query("SELECT estado FROM seats WHERE id = ?", [seatId], (err, rows) => {
      if (err || !rows.length) return;

      if (rows[0].estado !== "libre") return;

      db.query("UPDATE seats SET estado = 'retenido' WHERE id = ?", [seatId], () => {
        publicState((e, s) => io.emit("state", s));
      });
    });
  });

  socket.on('release-seat', ({ seatId }) => {
    db.query("UPDATE seats SET estado = 'libre' WHERE id = ?", [seatId], () => {
      publicState((e, s) => io.emit("state", s));
    });
  });

  socket.on('reset-seats', () => {
    if (!socket.user || socket.user.role !== "admin") return;

    db.query("UPDATE seats SET estado = 'libre'", () => {
      publicState((e, s) => io.emit("state", s));
    });
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
