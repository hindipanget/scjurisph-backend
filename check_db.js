const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, 'data', 'db_recent.db');
const db = new sqlite3.Database(dbPath);
db.all('SELECT pdf_filename FROM sandiganbayan_issuances LIMIT 5', (err, rows) => {
    if (err) console.error(err);
    else console.log(rows);
});
