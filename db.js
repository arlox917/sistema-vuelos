const mysql = require('mysql2/promise');

const db = mysql.createPool({
  host: 'gateway01-privatelink.us-west-2.prod.aws.tidbcloud.com',
  port: 4000,
  user: '2UJfnfeYBh113YFR.root',
  password: 'FIx4jftwCWtZ2cuk',
  database: 'flightdb',
  ssl: {
    minVersion: 'TLSv1.2',
    rejectUnauthorized: true
  }
});

module.exports = db;

