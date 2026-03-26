const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./database.sqlite');

const desiredPlans = [
  { name: 'Standard', description: 'Standard', price: 2000, duration: 30, daily_limit: 5, withdraw_limit: 500, estimated_profit: '2800', status: 'active' },
  { name: 'Silver', description: 'Most Valuable Plan', price: 5000, duration: 30, daily_limit: 10, withdraw_limit: 1200, estimated_profit: '7000', status: 'active' },
  { name: 'Gold', description: 'Most Valuable Plan', price: 11800, duration: 30, daily_limit: 10, withdraw_limit: 2000, estimated_profit: '17100', status: 'active' },
  { name: 'Diamond', description: 'Most Valuable Plan', price: 18400, duration: 30, daily_limit: 10, withdraw_limit: 3000, estimated_profit: '26500', status: 'active' },
  { name: 'Platinum', description: 'Platinum for users', price: 26500, duration: 30, daily_limit: 10, withdraw_limit: 3000, estimated_profit: '39800', status: 'active' },
  { name: 'VIP', description: 'Elite Vip Plan', price: 50000, duration: 30, daily_limit: 10, withdraw_limit: 3000, estimated_profit: '75000', status: 'active' },
  { name: 'VIP 2', description: 'Elite Vip Plan', price: 80000, duration: 30, daily_limit: 15, withdraw_limit: 5000, estimated_profit: '120000', status: 'active' },
  { name: 'VIP 3', description: 'Elite Vip Plan', price: 100000, duration: 30, daily_limit: 15, withdraw_limit: 10000, estimated_profit: '160000', status: 'active' }
];

db.serialize(() => {
  db.all('SELECT id, name, price FROM plans', (err, rows) => {
    if (err) {
      console.error(err);
      db.close();
      process.exit(1);
      return;
    }

    const maxPrice = Math.max(0, ...(rows || []).map(r => Number(r.price) || 0));
    const seedLike = (rows || []).length > 0 && (rows || []).length <= 4 && maxPrice <= 1000;
    const byName = new Map((rows || []).map(r => [String(r.name || ''), r]));
    const now = new Date().toISOString();

    const insertStmt = db.prepare('INSERT INTO plans (name, description, price, duration, daily_limit, withdraw_limit, estimated_profit, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)');
    const updateStmt = db.prepare('UPDATE plans SET description = ?, price = ?, duration = ?, daily_limit = ?, withdraw_limit = ?, estimated_profit = ?, status = ? WHERE id = ?');

    desiredPlans.forEach(p => {
      const existing = byName.get(p.name);
      if (existing) {
        if (seedLike) {
          updateStmt.run(p.description, p.price, p.duration, p.daily_limit, p.withdraw_limit, p.estimated_profit, p.status, existing.id);
        }
      } else {
        insertStmt.run(p.name, p.description, p.price, p.duration, p.daily_limit, p.withdraw_limit, p.estimated_profit, p.status, now);
      }
    });

    insertStmt.finalize();
    updateStmt.finalize();

    db.all('SELECT name, price, duration, daily_limit, withdraw_limit, estimated_profit, status FROM plans ORDER BY price ASC', (e2, out) => {
      if (e2) {
        console.error(e2);
        db.close();
        process.exit(1);
        return;
      }
      console.log(out);
      db.close();
    });
  });
});

