const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('database.sqlite');

db.all("PRAGMA table_info(chat_messages)", (err, rows) => {
    if (err) {
        console.error(err);
    } else {
        console.log("Chat Messages Table Schema:", rows);
    }
});