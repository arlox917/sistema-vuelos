const mysql = require('mysql2');

const db = mysql.createPool({
  host: 'localhost',
  user: 'admin',
  password: 'admin',
  database: 'flightdb'
});

module.exports = db;
