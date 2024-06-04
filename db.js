const Pool = require('pg').Pool;

// Openshift
const pool = new Pool({
    user: "postgres",
    host: "172.33.51.241",
    database: "aramco_mysecurity",
    password: "admin123",
    port: 5432
});

// Local
// const pool = new Pool({
//     user: "postgres",
//     host: "localhost",
//     database: "aramco_mysecurity",
//     password: "postgres",
//     port: 5432
// });


module.exports = pool;