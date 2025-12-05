// debug_users.js
const db = require('./db');

console.log('🔍 DEBUG: Verificando usuarios en la base de datos\n');

db.query('SELECT id, username, email, password, role, LENGTH(password) as pass_length FROM users', (err, results) => {
  if (err) {
    console.error('❌ Error de base de datos:', err.message);
    process.exit(1);
  }
  
  console.log(`📊 Total usuarios encontrados: ${results.length}\n`);
  
  if (results.length === 0) {
    console.log('⚠️  No hay usuarios en la base de datos.');
  } else {
    results.forEach((user, index) => {
      console.log(`👤 Usuario #${index + 1}:`);
      console.log(`   ID: ${user.id}`);
      console.log(`   Username: ${user.username}`);
      console.log(`   Email: ${user.email}`);
      console.log(`   Password (hash): ${user.password.substring(0, 20)}...`);
      console.log(`   Longitud hash: ${user.pass_length} caracteres`);
      console.log(`   Rol: ${user.role}`);
      console.log('   ---');
    });
  }
  
  // Verificar la tabla structure
  console.log('\n📋 Estructura de la tabla users:');
  db.query('DESCRIBE users', (descErr, descResults) => {
    if (descErr) {
      console.error('❌ Error obteniendo estructura:', descErr.message);
    } else {
      descResults.forEach(col => {
        console.log(`   ${col.Field}: ${col.Type} (${col.Null === 'YES' ? 'NULL' : 'NOT NULL'})`);
      });
    }
    process.exit(0);
  });
});