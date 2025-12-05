// setup_admin_interactive.js
const readline = require('readline');
const bcrypt = require('bcrypt');
const db = require('./db');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

console.log('🛠️  Configuración de Administrador\n');

rl.question('👉 Nombre de usuario: ', (username) => {
  rl.question('👉 Correo electrónico: ', (email) => {
    rl.question('👉 Contraseña: ', async (password) => {
      try {
        const hash = await bcrypt.hash(password, 10);
        
        db.query(
          'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)',
          [username, email, hash, 'admin'],
          (err, result) => {
            if (err) {
              console.error('\n❌ Error:', err.message);
            } else {
              console.log('\n✅ ¡Administrador creado exitosamente!');
              console.log('=========================================');
              console.log(`👤 Usuario: ${username}`);
              console.log(`📧 Email: ${email}`);
              console.log(`🎯 Rol: admin`);
              console.log(`🆔 ID: ${result.insertId}`);
            }
            rl.close();
            process.exit(0);
          }
        );
      } catch (error) {
        console.error('\n❌ Error:', error.message);
        rl.close();
        process.exit(1);
      }
    });
  });
});