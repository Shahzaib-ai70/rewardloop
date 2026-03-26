const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

function nicePaySign(params, key) {
  const keys = Object.keys(params || {}).filter(
    (k) =>
      k !== 'sign' &&
      params[k] !== '' &&
      params[k] !== null &&
      params[k] !== undefined &&
      !Array.isArray(params[k])
  );
  keys.sort();
  const base = keys.map((k) => `${k}=${params[k]}`).join('&');
  return crypto.createHash('md5').update(`${base}&key=${key}`).digest('hex').toUpperCase();
}

function nowIso() {
  return new Date().toISOString();
}

function run() {
  const db = new sqlite3.Database('database.sqlite');
  const key = process.env.NICEPAY_KEY || 'abcdefg';
  const merchantId = process.env.NICEPAY_MERCHANT_ID || '1000001';

  db.serialize(() => {
    db.run(
      "CREATE TABLE IF NOT EXISTS payment_orders (id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, out_order_number TEXT UNIQUE, user_id INTEGER, order_type TEXT, plan_id INTEGER, amount REAL, status TEXT DEFAULT 'pending', created_at TEXT, paid_at TEXT)"
    );

    db.get("SELECT id FROM users ORDER BY id ASC LIMIT 1", (e, u) => {
      if (e) throw e;
      const userId = (u && u.id) || 1;

      db.get("SELECT id, price, duration FROM plans WHERE status='active' ORDER BY id ASC LIMIT 1", (e2, p) => {
        if (e2) throw e2;
        const planId = (p && p.id) || 1;
        const amount = String((p && p.price) != null ? p.price : 10);
        const outOrderNumber = `SUB-${planId}-cb-sim-${Date.now()}-${userId}`;

        db.run(
          "INSERT OR REPLACE INTO payment_orders (provider,out_order_number,user_id,order_type,plan_id,amount,status,created_at) VALUES (?,?,?,?,?,?,?,?)",
          ['nicepay', outOrderNumber, userId, 'subscription', planId, Number(amount), 'pending', nowIso()],
          (e3) => {
            if (e3) throw e3;

            const payload = {
              merchant_id: merchantId,
              order_number: 'aaaabbbbcccdddd',
              out_order_number: outOrderNumber,
              status: 2,
              amount,
              real_amount: amount,
              callback_type: 'order'
            };

            const sign = nicePaySign({ ...payload, action: 'callback' }, key);
            const realAmount = Number(payload.real_amount);

            db.get(
              "SELECT * FROM payment_orders WHERE provider='nicepay' AND out_order_number=?",
              [outOrderNumber],
              (e4, order) => {
                if (e4) throw e4;
                if (!order) throw new Error('order not found');
                if (Number(order.amount) !== realAmount) throw new Error('real_amount mismatch');
                if (sign !== nicePaySign({ ...payload, action: 'callback' }, key)) throw new Error('sign mismatch');

                db.run(
                  "UPDATE payment_orders SET status='paid', paid_at=? WHERE id=?",
                  [nowIso(), order.id],
                  () => {
                    db.run(
                      "INSERT OR IGNORE INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                      [userId, Number(amount), 'NicePay Subscription', outOrderNumber, 'approved', nowIso(), null],
                      () => {
                        const expiry = new Date(
                          Date.now() + Number((p && p.duration) || 0) * 24 * 60 * 60 * 1000
                        ).toISOString();
                        db.run(
                          'UPDATE users SET plan_id=?, plan_expiry=? WHERE id=?',
                          [planId, expiry, userId],
                          () => {
                            db.get(
                              'SELECT status FROM payment_orders WHERE out_order_number=?',
                              [outOrderNumber],
                              (e6, r) => {
                                if (e6) throw e6;
                                db.get(
                                  'SELECT plan_id, plan_expiry FROM users WHERE id=?',
                                  [userId],
                                  (e7, ur) => {
                                    if (e7) throw e7;
                                    console.log(
                                      JSON.stringify({
                                        out_order_number: outOrderNumber,
                                        order_status: r.status,
                                        user_plan_id: ur.plan_id,
                                        user_plan_expiry: ur.plan_expiry
                                      })
                                    );
                                    db.close();
                                  }
                                );
                              }
                            );
                          }
                        );
                      }
                    );
                  }
                );
              }
            );
          }
        );
      });
    });
  });
}

run();
