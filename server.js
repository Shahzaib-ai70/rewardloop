const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const multer = require('multer');
const crypto = require('crypto');

// Configure Multer for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/')
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname)
    }
});
const upload = multer({ storage: storage });
const communityUpload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 },
    fileFilter: function (req, file, cb) {
        const t = (file && file.mimetype ? String(file.mimetype) : '').toLowerCase();
        if (t.startsWith('image/') || t.startsWith('video/')) return cb(null, true);
        return cb(new Error('Invalid file type'));
    }
});

const app = express();
const port = process.env.PORT || 3009;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Ensure JSON body parsing is available globally

// 1. Session Middleware (Moved to Top)
app.use(session({
    store: new SQLiteStore({ 
        db: 'sessions.db', 
        dir: '.',
        concurrentDb: true // Enable WAL mode if supported/helps
    }),
    secret: 'ptc-tasks-secret-key',
    resave: false, // Prevent unnecessary writes
    saveUninitialized: false,
    rolling: false, // Disable rolling to prevent write-storm on static assets
    cookie: { 
        maxAge: 7 * 24 * 60 * 60 * 1000, // 1 week
        httpOnly: true
    }
}));

// 2. Security & Auth Middleware (Before Static)
app.use((req, res, next) => {
    const url = req.path.toLowerCase();

    // Block sensitive files
    if (url.endsWith('.sqlite') || url.endsWith('.db') || url.endsWith('server.js')) {
        return res.status(403).send('Forbidden');
    }

    const userPages = ['/dashboard.html', '/ads.html', '/deposit.html', '/withdraw.html', '/settings.html', '/support.html', '/community.html'];

    // Admin Page Protection
    if (url.startsWith('/admin_') && url.endsWith('.html') && url !== '/admin_login.html') {
        if (!req.session.user) {
            return res.redirect('/admin_login.html');
        }
        
        // Auto-fix for legacy super_admin session
        if (req.session.user.role === 'super_admin') {
            req.session.user.role = 'admin';
        }

        if (req.session.user.role !== 'admin') {
            // If logged in as user (e.g. impersonating) but trying to access admin area,
            // redirect to admin login instead of user dashboard to avoid confusion.
            return res.redirect('/admin_login.html');
        }
        
        // Keep session alive when navigating admin pages
        req.session.touch();
    }
    
    // User Page Protection (Optional, but good consistency)
    if (userPages.includes(url)) {
        if (!req.session.user) {
            return res.redirect('/login.html');
        }
        if (req.session.user.role === 'user' && !req.session.adminId) {
            return db.get("SELECT is_banned FROM users WHERE id = ?", [req.session.user.id], (bErr, bRow) => {
                if (!bErr && bRow && Number(bRow.is_banned) === 1) {
                    return req.session.destroy(() => res.redirect('/login.html?banned=1'));
                }
                req.session.touch();
                next();
            });
        }
        req.session.touch();
        return next();
    }

    if (req.session.user && req.session.user.role === 'user' && !req.session.adminId && url.startsWith('/api/')) {
        return db.get("SELECT is_banned FROM users WHERE id = ?", [req.session.user.id], (bErr, bRow) => {
            if (!bErr && bRow && Number(bRow.is_banned) === 1) {
                return req.session.destroy(() => res.status(403).json({ error: 'Your account is banned. Contact customer service.' }));
            }
            next();
        });
    }

    next();
});

// Explicit Admin Routes (Before Static to prevent caching/routing issues)
app.get('/admin_dashboard.html', (req, res) => {
    if (req.session.user && req.session.user.role === 'admin') {
        res.sendFile(path.join(__dirname, 'admin_dashboard.html'));
    } else {
        res.redirect('/admin_login.html');
    }
});

app.get('/admin_login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin_login.html'));
});

// 3. Static Files
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Home Route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Database setup
const db = new sqlite3.Database('database.sqlite'); // Using file-based DB for persistence

db.serialize(() => {
    // Create users table if not exists
    db.run("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, firstname TEXT, lastname TEXT, username TEXT, email TEXT, country TEXT, phone TEXT, referral TEXT, gender TEXT, password TEXT, address TEXT, city TEXT, zip TEXT, dob TEXT, created_at TEXT, role TEXT DEFAULT 'user', balance REAL DEFAULT 0.0)");

    // Check if 'role' column exists (for migration)
    db.all("PRAGMA table_info(users)", (err, rows) => {
        if (err) {
            console.error("Error checking table info:", err);
            return;
        }
        const hasRole = rows.some(row => row.name === 'role');
        const hasBalance = rows.some(row => row.name === 'balance');

        if (!hasRole) {
            db.run("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'user'", (err) => {
                if (err) console.error("Error adding role column:", err);
                else {
                    console.log("Added 'role' column to users table.");
                    createAdmin();
                }
            });
        } else {
            createAdmin();
        }

        if (!hasBalance) {
            db.run("ALTER TABLE users ADD COLUMN balance REAL DEFAULT 0.0", (err) => {
                if (err) console.error("Error adding balance column:", err);
                else console.log("Added 'balance' column to users table.");
            });
        }
        
        // Add reward_balance column if not exists
        const hasRewardBalance = rows.some(row => row.name === 'reward_balance');
        if (!hasRewardBalance) {
            db.run("ALTER TABLE users ADD COLUMN reward_balance REAL DEFAULT 0.0", (err) => {
                if (err) console.error("Error adding reward_balance column:", err);
                else console.log("Added 'reward_balance' column to users table.");
            });
        }

        const hasPlanId = rows.some(row => row.name === 'plan_id');
        if (!hasPlanId) {
            db.run("ALTER TABLE users ADD COLUMN plan_id INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding plan_id column:", err);
                else console.log("Added 'plan_id' column to users table.");
            });
            db.run("ALTER TABLE users ADD COLUMN plan_expiry TEXT", (err) => {
                if (err) console.error("Error adding plan_expiry column:", err);
            });
        }

        const hasWithdrawalError = rows.some(row => row.name === 'withdrawal_error_active');
        if (!hasWithdrawalError) {
            db.run("ALTER TABLE users ADD COLUMN withdrawal_error_active INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding withdrawal_error_active column:", err);
                else console.log("Added 'withdrawal_error_active' column to users table.");
            });
            db.run("ALTER TABLE users ADD COLUMN withdrawal_error_text TEXT", (err) => {
                if (err) console.error("Error adding withdrawal_error_text column:", err);
                else console.log("Added 'withdrawal_error_text' column to users table.");
            });
        }

        const hasPlanStartedAt = rows.some(row => row.name === 'plan_started_at');
        if (!hasPlanStartedAt) {
            db.run("ALTER TABLE users ADD COLUMN plan_started_at TEXT", (err) => {
                if (err) console.error("Error adding plan_started_at column:", err);
            });
        }

        const hasPlanAdsUsed = rows.some(row => row.name === 'plan_ads_used');
        if (!hasPlanAdsUsed) {
            db.run("ALTER TABLE users ADD COLUMN plan_ads_used INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding plan_ads_used column:", err);
            });
        }

        const hasPlanAdsTotal = rows.some(row => row.name === 'plan_ads_total');
        if (!hasPlanAdsTotal) {
            db.run("ALTER TABLE users ADD COLUMN plan_ads_total INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding plan_ads_total column:", err);
            });
        }

        const hasDoubleProfitUnlocked = rows.some(row => row.name === 'double_profit_unlocked');
        if (!hasDoubleProfitUnlocked) {
            db.run("ALTER TABLE users ADD COLUMN double_profit_unlocked INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding double_profit_unlocked column:", err);
            });
        }

        const hasDoubleProfitBonusPct = rows.some(row => row.name === 'double_profit_bonus_pct');
        if (!hasDoubleProfitBonusPct) {
            db.run("ALTER TABLE users ADD COLUMN double_profit_bonus_pct REAL DEFAULT 0", (err) => {
                if (err) console.error("Error adding double_profit_bonus_pct column:", err);
            });
        }

        const hasDoubleProfitUnlockedAt = rows.some(row => row.name === 'double_profit_unlocked_at');
        if (!hasDoubleProfitUnlockedAt) {
            db.run("ALTER TABLE users ADD COLUMN double_profit_unlocked_at TEXT", (err) => {
                if (err) console.error("Error adding double_profit_unlocked_at column:", err);
            });
        }

        const hasDoubleProfitDisabled = rows.some(row => row.name === 'double_profit_disabled');
        if (!hasDoubleProfitDisabled) {
            db.run("ALTER TABLE users ADD COLUMN double_profit_disabled INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding double_profit_disabled column:", err);
            });
        }

        const hasIsBanned = rows.some(row => row.name === 'is_banned');
        if (!hasIsBanned) {
            db.run("ALTER TABLE users ADD COLUMN is_banned INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding is_banned column:", err);
            });
        }

        const hasCommunityJoined = rows.some(row => row.name === 'community_joined');
        if (!hasCommunityJoined) {
            db.run("ALTER TABLE users ADD COLUMN community_joined INTEGER DEFAULT 0", (err) => {
                if (err) console.error("Error adding community_joined column:", err);
            });
        }

        const hasCommunityJoinedAt = rows.some(row => row.name === 'community_joined_at');
        if (!hasCommunityJoinedAt) {
            db.run("ALTER TABLE users ADD COLUMN community_joined_at TEXT", (err) => {
                if (err) console.error("Error adding community_joined_at column:", err);
            });
        }
    });

    // Check if 'withdraw_limit' column exists in plans
    db.all("PRAGMA table_info(plans)", (err, rows) => {
        if (!err) {
            const hasLimit = rows.some(row => row.name === 'withdraw_limit');
            if (!hasLimit) {
                db.run("ALTER TABLE plans ADD COLUMN withdraw_limit REAL DEFAULT 0", (err) => {
                    if (err) console.error("Error adding withdraw_limit column to plans:", err);
                    else console.log("Added 'withdraw_limit' column to plans table.");
                });
            }

            const hasProfit = rows.some(row => row.name === 'estimated_profit');
            if (!hasProfit) {
                db.run("ALTER TABLE plans ADD COLUMN estimated_profit TEXT", (err) => {
                    if (err) console.error("Error adding estimated_profit column to plans:", err);
                    else console.log("Added 'estimated_profit' column to plans table.");
                });
            }

            const hasDpAfterAds = rows.some(row => row.name === 'double_profit_after_ads');
            if (!hasDpAfterAds) {
                db.run("ALTER TABLE plans ADD COLUMN double_profit_after_ads INTEGER DEFAULT 0", (err) => {
                    if (err) console.error("Error adding double_profit_after_ads column to plans:", err);
                });
            }

            const hasDpFee = rows.some(row => row.name === 'double_profit_fee');
            if (!hasDpFee) {
                db.run("ALTER TABLE plans ADD COLUMN double_profit_fee REAL DEFAULT 0", (err) => {
                    if (err) console.error("Error adding double_profit_fee column to plans:", err);
                });
            }

            const hasDpBonus = rows.some(row => row.name === 'double_profit_bonus_pct');
            if (!hasDpBonus) {
                db.run("ALTER TABLE plans ADD COLUMN double_profit_bonus_pct REAL DEFAULT 0", (err) => {
                    if (err) console.error("Error adding double_profit_bonus_pct column to plans:", err);
                });
            }
        }
    });

    function createAdmin() {
        // Create default admin user
        const adminUser = {
            firstname: 'Admin',
            lastname: 'User',
            username: 'admin',
            email: 'admin@example.com',
            password: 'admin123', // In production, hash this!
            role: 'admin',
            created_at: new Date().toISOString()
        };

        db.get("SELECT * FROM users WHERE username = ?", [adminUser.username], (err, row) => {
            if (!row) {
                const stmt = db.prepare("INSERT INTO users (firstname, lastname, username, email, password, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
                stmt.run(adminUser.firstname, adminUser.lastname, adminUser.username, adminUser.email, adminUser.password, adminUser.role, adminUser.created_at);
                stmt.finalize();
                console.log("Default admin account created.");
            }
        });
    }

    // Create ads table
    db.run("CREATE TABLE IF NOT EXISTS ads (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, url TEXT, duration INTEGER, reward REAL, status TEXT DEFAULT 'active', created_at TEXT, plan_id INTEGER)");

    // Check if 'plan_id' column exists in ads
    db.all("PRAGMA table_info(ads)", (err, rows) => {
        if (!err) {
            const hasPlanId = rows.some(row => row.name === 'plan_id');
            if (!hasPlanId) {
                db.run("ALTER TABLE ads ADD COLUMN plan_id INTEGER", (err) => {
                    if (err) console.error("Error adding plan_id column to ads:", err);
                    else console.log("Added 'plan_id' column to ads table.");
                });
            }
            
            const hasStatus = rows.some(row => row.name === 'status');
            if (!hasStatus) {
                db.run("ALTER TABLE ads ADD COLUMN status TEXT DEFAULT 'active'", (err) => {
                    if (err) console.error("Error adding status column to ads:", err);
                    else console.log("Added 'status' column to ads table.");
                });
            }
        }
    });
    
    // Create other necessary tables for admin management
    db.run("CREATE TABLE IF NOT EXISTS deposits (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, gateway TEXT, transaction_id TEXT, status TEXT DEFAULT 'pending', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS withdrawals (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, method TEXT, account_details TEXT, status TEXT DEFAULT 'pending', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS kyc_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT, details TEXT, photo_path TEXT, status TEXT DEFAULT 'pending', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS support_tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, subject TEXT, priority TEXT, message TEXT, status TEXT DEFAULT 'open', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS ticket_replies (id INTEGER PRIMARY KEY AUTOINCREMENT, ticket_id INTEGER, sender TEXT, message TEXT, created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS payment_methods (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, account_number TEXT, currency TEXT, rate REAL, min_amount REAL, max_amount REAL, instructions TEXT, image_path TEXT, status TEXT DEFAULT 'active', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS payment_orders (id INTEGER PRIMARY KEY AUTOINCREMENT, provider TEXT, out_order_number TEXT UNIQUE, user_id INTEGER, order_type TEXT, plan_id INTEGER, amount REAL, status TEXT DEFAULT 'pending', created_at TEXT, paid_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS nicepay_sync_history (id INTEGER PRIMARY KEY AUTOINCREMENT, out_order_number TEXT, admin_id INTEGER, admin_username TEXT, endpoint TEXT, result TEXT, response_code INTEGER, response_status TEXT, response_amount REAL, response_real_amount REAL, response_msg TEXT, response_json TEXT, created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS double_profit_purchases (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan_id INTEGER, fee REAL, bonus_pct REAL, created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS double_profit_offers (id INTEGER PRIMARY KEY AUTOINCREMENT, plan_id INTEGER, after_ads INTEGER, fee REAL, bonus_pct REAL, status TEXT DEFAULT 'active', created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS double_profit_offer_purchases (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, plan_id INTEGER, ad_id INTEGER, offer_id INTEGER, offer_after_ads INTEGER, fee REAL, bonus_pct REAL, used_at TEXT, created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS transfers (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_id INTEGER, receiver_id INTEGER, amount REAL, created_at TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)");
    db.run("CREATE TABLE IF NOT EXISTS community_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender_type TEXT, sender_user_id INTEGER, sender_name TEXT, message TEXT, reply_to TEXT, created_at TEXT)");
    db.all("PRAGMA table_info(community_messages)", (err, rows) => {
        if (err) return;
        const hasMediaUrl = rows.some(r => r.name === 'media_url');
        if (!hasMediaUrl) {
            db.run("ALTER TABLE community_messages ADD COLUMN media_url TEXT", () => {});
        }
        const hasMediaKind = rows.some(r => r.name === 'media_kind');
        if (!hasMediaKind) {
            db.run("ALTER TABLE community_messages ADD COLUMN media_kind TEXT", () => {});
        }
        const hasMediaName = rows.some(r => r.name === 'media_name');
        if (!hasMediaName) {
            db.run("ALTER TABLE community_messages ADD COLUMN media_name TEXT", () => {});
        }
    });
    
    // Check if chat_messages table exists, if not create it (Fix for live chat)
    db.get("SELECT name FROM sqlite_master WHERE type='table' AND name='chat_messages'", (err, row) => {
        if (!row) {
            console.log("Creating chat_messages table...");
            db.run("CREATE TABLE IF NOT EXISTS chat_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, sender TEXT, message TEXT, is_read INTEGER DEFAULT 0, created_at TEXT)");
        }
    });

    db.all("PRAGMA table_info(double_profit_offer_purchases)", (err, rows) => {
        if (err) return;
        const hasOutOrder = rows.some(r => r.name === 'out_order_number');
        if (!hasOutOrder) {
            db.run("ALTER TABLE double_profit_offer_purchases ADD COLUMN out_order_number TEXT", () => {});
        }
        const hasPaymentStatus = rows.some(r => r.name === 'payment_status');
        if (!hasPaymentStatus) {
            db.run("ALTER TABLE double_profit_offer_purchases ADD COLUMN payment_status TEXT DEFAULT 'paid'", () => {});
        }
        const hasPaidAt = rows.some(r => r.name === 'paid_at');
        if (!hasPaidAt) {
            db.run("ALTER TABLE double_profit_offer_purchases ADD COLUMN paid_at TEXT", () => {});
        }
    });
    
    db.run("CREATE TABLE IF NOT EXISTS reviews (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, language TEXT, content TEXT, created_at TEXT, is_approved INTEGER DEFAULT 1)", () => {
         // Auto seed reviews if empty
         db.get("SELECT COUNT(*) as count FROM reviews", (err, row) => {
             if (!err && row && row.count === 0) {
                 const englishReviews = [
                     "Amazing platform, highly recommended!", "Fast withdrawals and great support.", "Best investment site I have ever used.",
                     "Very reliable and trustworthy.", "I made a good profit here, thanks!", "Customer service is top notch.",
                     "Easy to use interface.", "I love the referral program.", "Smooth transactions every time.", "Will definitely invest more.",
                     "Legit paying site.", "Good ROI on plans.", "I am very satisfied with this platform."
                 ];
                 const urduReviews = [
                     "Bohat achi website hai, zaroor try karein.", "Withdrawal jaldi mil jata hai.", "Bhtrin platform profit ke liye.",
                     "Bharosemand aur asan.", "Mera tajurba bohat acha raha.", "Customer support bohat co-operative hai.",
                     "Asan istemal.", "Referral program bohat munasib hai.", "Transactions bina kisi masle ke hoti hain.", "Main mazeed invest karunga.",
                     "100% real website hai.", "Profit time pe milta hai."
                 ];
                 const names = ["Ali", "Sarah", "Ahmed", "Ayesha", "John", "Fatima", "Usman", "Zainab", "Hassan", "Khadija", "Umar", "Maryam", "Bilal", "Sana"];
                 
                 const stmt = db.prepare("INSERT INTO reviews (username, language, content, created_at, is_approved) VALUES (?, ?, ?, ?, ?)");
                 for (let i = 0; i < 300; i++) {
                     const isEnglish = Math.random() > 0.5;
                     const lang = isEnglish ? 'en' : 'ur';
                     const contentPool = isEnglish ? englishReviews : urduReviews;
                     const username = names[Math.floor(Math.random() * names.length)] + Math.floor(Math.random() * 1000);
                     const content = contentPool[Math.floor(Math.random() * contentPool.length)];
                     stmt.run(username, lang, content, new Date().toISOString(), 1);
                 }
                 stmt.finalize();
                 console.log("Auto-seeded 300 reviews.");
             }
         });
     });
    
    // Ensure settings table has default values
    db.get("SELECT value FROM settings WHERE key = 'referral_signup_bonus'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO settings (key, value) VALUES ('referral_signup_bonus', '0')");
        }
    });
    db.get("SELECT value FROM settings WHERE key = 'joining_bonus'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO settings (key, value) VALUES ('joining_bonus', '0')");
        }
    });
    db.get("SELECT value FROM settings WHERE key = 'referral_deposit_commission_pct'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO settings (key, value) VALUES ('referral_deposit_commission_pct', '10')");
        }
    });
    db.get("SELECT value FROM settings WHERE key = 'subscription_help_media'", (err, row) => {
        if (!row) {
            db.run("INSERT INTO settings (key, value) VALUES ('subscription_help_media', '')");
        }
    });
    
    // Create plans table
    db.run("CREATE TABLE IF NOT EXISTS plans (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, description TEXT, price REAL, duration INTEGER, daily_limit INTEGER, withdraw_limit REAL DEFAULT 0, estimated_profit TEXT, double_profit_after_ads INTEGER DEFAULT 0, double_profit_fee REAL DEFAULT 0, double_profit_bonus_pct REAL DEFAULT 0, status TEXT DEFAULT 'active', created_at TEXT)", (err) => {
        if (err) return;

        const autoSeedPlans = String(process.env.AUTO_SEED_DEFAULT_PLANS || '').trim() === '1';
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

        db.all("SELECT id, name FROM plans", (err, rows) => {
            if (err) return;

            const byName = new Map((rows || []).map(r => [String(r.name || ''), r]));
            const now = new Date().toISOString();

            const shouldSeed = autoSeedPlans || rows.length === 0;
            if (!shouldSeed) return;

            const insertStmt = db.prepare("INSERT INTO plans (name, description, price, duration, daily_limit, withdraw_limit, estimated_profit, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            desiredPlans.forEach(p => {
                if (byName.has(p.name)) return;
                insertStmt.run(p.name, p.description, p.price, p.duration, p.daily_limit, p.withdraw_limit, p.estimated_profit, 0, 0, 0, p.status, now);
            });
            insertStmt.finalize();
        });
    });

    // Create portfolios table
    db.run("CREATE TABLE IF NOT EXISTS portfolios (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, level INTEGER, min_transactions REAL, bonus REAL, description TEXT, status TEXT DEFAULT 'active', created_at TEXT)", (err) => {
        if (!err) {
            // Seed default portfolios
            db.get("SELECT COUNT(*) as count FROM portfolios", (err, row) => {
                if (!err && row && row.count === 0) {
                    console.log("Seeding default portfolios...");
                    const stmt = db.prepare("INSERT INTO portfolios (name, level, min_transactions, bonus, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
                    const now = new Date().toISOString();
                    
                    const defaultPortfolios = [
                        ['Solid Member', 1, 0, 0, 'By signing up to the account', 'active', now],
                        ['Solid Member Pro', 2, 100, 20, 'Earn exclusive rewards that celebrate your achievements', 'active', now],
                        ['Solid Max Member', 3, 1000, 100, 'Earn exclusive rewards for your loyalty and participation', 'active', now]
                    ];
                    
                    defaultPortfolios.forEach(p => {
                        stmt.run(...p);
                    });
                    stmt.finalize();
                }
            });
        }
    });

    // Seed Ads if less than 100 active
    db.get("SELECT COUNT(*) as count FROM ads WHERE status = 'active'", (err, row) => {
        const keepMinimumActiveAds = String(process.env.KEEP_MINIMUM_ACTIVE_ADS || '').trim() === '1';
        if (!keepMinimumActiveAds) return;
        if (!err && row && row.count < 100) {
            const needed = 100 - row.count;
            console.log(`Seeding ${needed} random ads to reach minimum 100...`);
            const stmt = db.prepare("INSERT INTO ads (title, url, duration, reward, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
            const now = new Date().toISOString();

            // Helper to get random number in range
            const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
            const randReward = () => (Math.random() * 4.5 + 0.5).toFixed(2); // 0.50 to 5.00

            const videoTitles = [
                "Relaxing Nature 4K",
                "Funny Cats Compilation",
                "Cute Puppies Playing",
                "Yoga for Beginners",
                "Meditation Music",
                "Science Documentary: Space",
                "History Documentary",
                "Learn JavaScript Basics",
                "Tech Review",
                "Travel Vlog",
                "Street Food Tour",
                "DIY Home Decor",
                "Fitness Workout Routine",
                "Cooking Recipe",
                "Motivational Speech"
            ];

            const youtubeIds = [
                "hY7m5jjJ9mM",
                "v7AYKMP6rOE",
                "U9BwWKXjVaI",
                "ScMzIvxBSi4",
                "WpTdAogP70M",
                "j5-yKhDd64s",
                "UnZWTuDDpKs",
                "34Na4j8AVgA",
                "7WTpNHjFNZM",
                "lTRiuFIWV54",
                "tgbNymZ7vqY",
                "PT2_F-1esPk",
                "0KSOMA3QBU0",
                "kJQP7kiw5Fk",
                "OPf0YbXqDm0"
            ];

            for (let i = 0; i < needed; i++) {
                // Use modulo to cycle through titles/ids if we need more than available
                const titleIndex = i % videoTitles.length;
                const idIndex = i % youtubeIds.length;
                
                const title = videoTitles[titleIndex];
                const vidId = youtubeIds[idIndex];
                const url = `https://www.youtube.com/watch?v=${vidId}`;
                const duration = rand(10, 60); // 10 to 60 seconds
                const reward = randReward();
                
                stmt.run(title, url, duration, reward, 'active', now);
            }
            stmt.finalize();
            console.log(`Successfully seeded ${needed} ads.`);
        }
    });

    setTimeout(() => {
        if (String(process.env.AUDIT_ADS_ON_STARTUP || '1').trim() === '1') {
            auditAdsToDisableUnavailable();
        }
    }, 4000);

    // Check if 'account_number' column exists in payment_methods
    db.all("PRAGMA table_info(payment_methods)", (err, rows) => {
        if (!err) {
            const hasAccNum = rows.some(row => row.name === 'account_number');
            if (!hasAccNum) {
                db.run("ALTER TABLE payment_methods ADD COLUMN account_number TEXT", (err) => {
                    if (err) console.error("Error adding account_number column:", err);
                    else console.log("Added 'account_number' column to payment_methods table.");
                });
            }
            
            const hasBankName = rows.some(row => row.name === 'bank_name');
            if (!hasBankName) {
                db.run("ALTER TABLE payment_methods ADD COLUMN bank_name TEXT", (err) => {
                    if (err) console.error("Error adding bank_name column:", err);
                    else console.log("Added 'bank_name' column to payment_methods table.");
                });
            }
        }
    });

    // Check if 'proof_image' column exists in deposits
    db.all("PRAGMA table_info(deposits)", (err, rows) => {
        if (!err) {
            const hasProof = rows.some(row => row.name === 'proof_image');
            if (!hasProof) {
                db.run("ALTER TABLE deposits ADD COLUMN proof_image TEXT", (err) => {
                    if (err) console.error("Error adding proof_image column:", err);
                    else console.log("Added 'proof_image' column to deposits table.");
                });
            }
        }
    });
});

let communityFakeTimer = null;
function startCommunityFakeFeed() {
    const isTruthy = (v) => {
        const s = String(v || '').trim().toLowerCase();
        return s === '1' || s === 'true' || s === 'yes' || s === 'on';
    };
    const clamp = (n, min, max) => {
        const x = Number(n);
        if (!Number.isFinite(x)) return min;
        return Math.min(max, Math.max(min, x));
    };
    const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

    const first = ['Ali','Ahmed','Ayesha','Fatima','Zain','Hassan','Hamza','Sara','Umar','Bilal','Maryam','Noor','Hina','Asad','Usman','Musa','Kiran','Iqra','Saad','Daniyal','Rida','Sana','Haris','Farhan','Amna','Anaya','Zoya','Areeba','Aqsa','Huzaifa'];
    const last = ['Khan','Malik','Sheikh','Butt','Raza','Iqbal','Hussain','Chaudhry','Siddiqui','Qureshi','Javed','Nawaz','Rashid','Mirza','Yousaf','Saleem','Haq','Shah','Ansari','Bhatti','Rehman','Akhtar','Abbasi','Kashif','Rafiq','Aziz','Junaid','Noman','Haider','Mehmood'];
    const templates = [
        'Anyone got today’s ads completed?',
        'Just withdrew successfully, thanks!',
        'What plan are you using right now?',
        'Good morning everyone!',
        'I upgraded my plan and earnings improved.',
        'Support replied fast today.',
        'Don’t forget to check rewards tab.',
        'My ads page is loading slow for me, anyone else?',
        'Referral bonus just received.',
        'Keep going, consistency matters.',
        'What’s your target for this week?',
        'Congrats on your withdrawal!',
        'Remember to submit proof correctly.',
        'Which wallet do you use for PKR?',
        'I just joined, nice to meet you all.',
        'Any tips for new users?',
        'Stay active and complete daily tasks.',
        'Let’s help each other.',
        'How many ads per day on VIP?',
        'Best time to do ads?',
        'I like the new updates.',
        'Please be careful with scammers.',
        'Always use official links.',
        'Anyone from Karachi here?',
        'Pakistan community is strong!',
        'Let’s share progress.',
        'Today’s earnings: decent.',
        'Keep the chat clean.',
        'I’m waiting for my plan activation.',
        'Admin will approve soon, be patient.'
    ];
    const plans = ['Silver', 'Gold', 'Diamond', 'Platinum', 'VIP', 'Standard'];
    const suffixes = [
        'Any update?',
        'Please guide.',
        'Thanks.',
        'Right now.',
        'Today.',
        'This week.',
        'Anyone else?'
    ];

    const recent = [];
    const recentSet = new Set();
    const remember = (t) => {
        const key = String(t || '');
        if (!key) return;
        recent.push(key);
        recentSet.add(key);
        while (recent.length > 140) {
            const r = recent.shift();
            recentSet.delete(r);
        }
    };
    const pickFresh = () => {
        for (let i = 0; i < 12; i++) {
            const t = pick(templates);
            if (!recentSet.has(t)) return t;
        }
        return pick(templates);
    };

    const loop = () => {
        if (communityFakeTimer) clearTimeout(communityFakeTimer);
        db.all("SELECT key, value FROM settings WHERE key IN ('community_enabled','community_fake_chat_enabled','community_fake_user_count','community_message_interval_ms')", (err, rows) => {
            const s = { community_enabled: '1', community_fake_chat_enabled: '1', community_fake_user_count: '400', community_message_interval_ms: '1100' };
            if (!err && rows) rows.forEach(r => { s[r.key] = r.value; });
            const enabled = isTruthy(s.community_enabled) && isTruthy(s.community_fake_chat_enabled);
            const base = clamp(s.community_message_interval_ms || 1100, 500, 5000);
            const nextDelay = enabled ? Math.round(base * (0.65 + Math.random() * 0.85)) : 10000;

            if (!enabled) {
                communityFakeTimer = setTimeout(loop, nextDelay);
                return;
            }

            const userCount = clamp(s.community_fake_user_count || 400, 300, 500);
            const senderName = `${pick(first)} ${pick(last)} ${String(Math.floor(Math.random() * 90) + 10)}`;
            const message = pickFresh();
            remember(message);
            const replyTo = null;
            const now = new Date().toISOString();
            db.run(
                "INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, created_at) VALUES ('fake', NULL, ?, ?, ?, ?)",
                [senderName, message, replyTo, now],
                () => {
                    communityFakeTimer = setTimeout(loop, nextDelay);
                }
            );
        });
    };

    db.get("SELECT COUNT(*) as c FROM community_messages", (err, row) => {
        const c = row && row.c ? Number(row.c) : 0;
        if (!err && c === 0) {
            const now = new Date().toISOString();
            const stmt = db.prepare("INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, created_at) VALUES ('fake', NULL, ?, ?, NULL, ?)");
            for (let i = 0; i < 30; i++) {
                const senderName = `${pick(first)} ${pick(last)} ${String(Math.floor(Math.random() * 90) + 10)}`;
                const message = pickFresh();
                remember(message);
                stmt.run(senderName, message, now);
            }
            stmt.finalize(() => loop());
            return;
        }
        loop();
    });
}

startCommunityFakeFeed();

// Admin API: Get User Details
app.get('/api/admin/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.get("SELECT * FROM users WHERE id = ?", [req.params.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!row) return res.status(404).json({ error: 'User not found' });
        res.json(row);
    });
});

// Admin API: Get Extended User Stats
app.get('/api/admin/users/:id/stats', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const userId = req.params.id;
    const stats = {};

    db.serialize(() => {
        // 1. Total Viewed Ads
        db.get("SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View'", [userId], (err, row) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            stats.viewedAds = row.count;

            // 2. Total Earnings (from Ads)
            db.get("SELECT SUM(amount) as total FROM deposits WHERE user_id = ? AND gateway = 'Ad View'", [userId], (err, row) => {
                stats.totalEarnings = row.total || 0;

                // 3. Total Deposit (Approved)
                db.get("SELECT SUM(amount) as total FROM deposits WHERE user_id = ? AND status = 'approved' AND gateway != 'Ad View'", [userId], (err, row) => {
                    stats.totalDeposit = row.total || 0;

                    // 4. Total Withdraw (Completed/Approved)
                    db.get("SELECT SUM(amount) as total FROM withdrawals WHERE user_id = ? AND status = 'approved'", [userId], (err, row) => {
                        stats.totalWithdraw = row.total || 0;

                        // 5. Total Transactions
                        db.get("SELECT COUNT(*) as count FROM deposits WHERE user_id = ? UNION ALL SELECT COUNT(*) as count FROM withdrawals WHERE user_id = ?", [userId, userId], (err, row) => {
                            // Simple count approximation
                            db.get("SELECT (SELECT COUNT(*) FROM deposits WHERE user_id = ?) + (SELECT COUNT(*) FROM withdrawals WHERE user_id = ?) as total", [userId, userId], (err, row) => {
                                stats.totalTransactions = row.total || 0;
                                res.json(stats);
                            });
                        });
                    });
                });
            });
        });
    });
});

// Admin API: Get User Earnings History
app.get('/api/admin/users/:id/earnings', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM deposits WHERE user_id = ? AND gateway = 'Ad View' ORDER BY id DESC", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Get User Viewed Ads
app.get('/api/admin/users/:id/viewed-ads', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    // Join with ads table to get titles
    db.all(`
        SELECT ads.title, deposits.amount, deposits.created_at 
        FROM deposits 
        JOIN ads ON deposits.transaction_id LIKE 'AD-' || ads.id || '-%'
        WHERE deposits.user_id = ? AND deposits.gateway = 'Ad View' 
        ORDER BY deposits.id DESC
    `, [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.get('/api/admin/users/:id/double-profit-tasks', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = Number(req.params.id);
    if (!Number.isFinite(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid user id' });
    }

    db.get("SELECT id, plan_id, plan_expiry, plan_started_at FROM users WHERE id = ?", [userId], (uErr, user) => {
        if (uErr) return res.status(500).json({ error: 'DB Error' });
        if (!user || !user.plan_id || new Date(user.plan_expiry) < new Date()) {
            return res.json({ active: false, tasks: [] });
        }

        db.get("SELECT id, duration, daily_limit FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
            if (pErr || !plan) return res.json({ active: false, tasks: [] });

            const expiry = new Date(user.plan_expiry);
            const isValidExpiry = !isNaN(expiry.getTime());
            const durationDays = Number(plan.duration) || 0;

            const parseIso = (v) => {
                const d = v ? new Date(v) : null;
                return d && !isNaN(d.getTime()) ? d.toISOString() : null;
            };

            const fromUser = parseIso(user.plan_started_at);

            const inferFromExpiry = () => {
                if (!isValidExpiry || durationDays <= 0) return null;
                const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                return start.toISOString();
            };

            const loadPlanStart = (cb) => {
                if (fromUser) return cb(fromUser);
                db.get(
                    "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                    [userId],
                    (sErr, sRow) => {
                        if (!sErr && sRow && sRow.created_at) {
                            const iso = parseIso(sRow.created_at);
                            if (iso) return cb(iso);
                        }
                        cb(inferFromExpiry());
                    }
                );
            };

            loadPlanStart((startIso) => {
                const start = startIso || inferFromExpiry() || new Date().toISOString();
                db.get(
                    "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                    [userId, start],
                    (cErr, cRow) => {
                        if (cErr) return res.status(500).json({ error: 'DB Error' });
                        const adsWatched = cRow && cRow.count ? Number(cRow.count) : 0;

                        db.all(
                            "SELECT id, after_ads, fee, bonus_pct, status FROM double_profit_offers WHERE plan_id = ? AND status = 'active' ORDER BY after_ads ASC, id ASC",
                            [user.plan_id],
                            (oErr, offers) => {
                                if (oErr) return res.status(500).json({ error: 'DB Error' });

                                db.all(
                                    "SELECT offer_after_ads, MAX(CASE WHEN used_at IS NULL AND (payment_status = 'paid' OR fee = 0) THEN 1 ELSE 0 END) AS has_pending, MAX(CASE WHEN used_at IS NULL AND (payment_status IS NULL OR payment_status = '' OR payment_status = 'pending') AND fee > 0 THEN 1 ELSE 0 END) AS has_pending_payment, MAX(CASE WHEN used_at IS NOT NULL THEN 1 ELSE 0 END) AS has_used FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND created_at >= ? GROUP BY offer_after_ads",
                                    [userId, user.plan_id, start],
                                    (hErr, rows) => {
                                        if (hErr) return res.status(500).json({ error: 'DB Error' });
                                        const map = new Map((rows || []).map(r => [Number(r.offer_after_ads), r]));

                                        const tasks = (offers || []).map(o => {
                                            const key = Number(o.after_ads) || 0;
                                            const stRow = map.get(key);
                                            const hasUsed = stRow && Number(stRow.has_used) === 1;
                                            const hasPending = stRow && Number(stRow.has_pending) === 1;
                                            const hasPendingPayment = stRow && Number(stRow.has_pending_payment) === 1;
                                            const status = hasUsed ? 'used' : (hasPendingPayment ? 'pending_payment' : (hasPending ? 'completed' : 'pending'));
                                            return {
                                                offer_id: o.id,
                                                after_ads: key,
                                                fee: Number(o.fee) || 0,
                                                bonus_pct: Number(o.bonus_pct) || 0,
                                                status
                                            };
                                        });

                                        res.json({
                                            active: true,
                                            plan_id: user.plan_id,
                                            ads_watched: adsWatched,
                                            tasks
                                        });
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    });
});

app.post('/api/user/double-profit/manual', upload.single('proof'), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const userId = req.session.user.id;
    const adId = req.body && req.body.ad_id !== undefined && req.body.ad_id !== null ? Number(req.body.ad_id) : null;
    const offerIdRaw = req.body && req.body.offer_id !== undefined && req.body.offer_id !== null ? Number(req.body.offer_id) : null;
    const methodId = req.body && req.body.method_id !== undefined && req.body.method_id !== null ? Number(req.body.method_id) : null;
    const proofImage = req.file ? '/uploads/' + req.file.filename : null;
    if (!Number.isFinite(adId) || adId <= 0) return res.status(400).json({ error: 'Invalid ad_id' });
    if (!Number.isFinite(methodId) || methodId <= 0) return res.status(400).json({ error: 'Invalid payment method' });
    if (!proofImage) return res.status(400).json({ error: 'Payment proof is required' });

    db.get("SELECT id, plan_id, plan_expiry, plan_started_at, plan_ads_total, double_profit_disabled FROM users WHERE id = ?", [userId], (uErr, user) => {
        if (uErr) return res.status(500).json({ error: 'DB Error' });
        if (!user || !user.plan_id || new Date(user.plan_expiry) < new Date()) return res.status(400).json({ error: 'No active plan' });
        if (Number(user.double_profit_disabled) === 1) return res.status(400).json({ error: 'Double profit disabled for this user' });

        db.get("SELECT id, duration, daily_limit, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
            if (pErr || !plan) return res.status(400).json({ error: 'Plan error' });

            const totalAllowed = Number(user.plan_ads_total) > 0 ? Number(user.plan_ads_total) : (Number(plan.daily_limit) || 0);
            if (totalAllowed <= 0) return res.status(400).json({ error: 'Plan error' });

            const expiry = new Date(user.plan_expiry);
            const isValidExpiry = !isNaN(expiry.getTime());
            const durationDays = Number(plan.duration) || 0;

            const parseIso = (v) => {
                const d = v ? new Date(v) : null;
                return d && !isNaN(d.getTime()) ? d.toISOString() : null;
            };

            const fromUser = parseIso(user.plan_started_at);

            const inferFromExpiry = () => {
                if (!isValidExpiry || durationDays <= 0) return null;
                const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                return start.toISOString();
            };

            const loadPlanStart = (cb) => {
                if (fromUser) return cb(fromUser);
                db.get(
                    "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                    [userId],
                    (sErr, sRow) => {
                        if (!sErr && sRow && sRow.created_at) {
                            const iso = parseIso(sRow.created_at);
                            if (iso) return cb(iso);
                        }
                        cb(inferFromExpiry());
                    }
                );
            };

            loadPlanStart((startIso) => {
                const start = startIso || inferFromExpiry() || new Date().toISOString();
                db.get(
                    "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                    [userId, start],
                    (cErr, cRow) => {
                        if (cErr) return res.status(500).json({ error: 'DB Error' });
                        const used = cRow && cRow.count ? Number(cRow.count) : 0;

                        const pickOffer = (cb) => {
                            if (Number.isFinite(offerIdRaw) && offerIdRaw > 0) {
                                db.get(
                                    "SELECT id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE id = ? AND plan_id = ? AND status = 'active' LIMIT 1",
                                    [offerIdRaw, user.plan_id],
                                    (oErr, offer) => cb(oErr, offer)
                                );
                                return;
                            }
                            db.get(
                                "SELECT id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE plan_id = ? AND status = 'active' AND after_ads = ? ORDER BY id ASC LIMIT 1",
                                [user.plan_id, used],
                                (oErr, offer) => cb(oErr, offer)
                            );
                        };

                        pickOffer((oErr, offer) => {
                            if (oErr) return res.status(500).json({ error: 'DB Error' });

                            const offerId = offer && offer.id ? Number(offer.id) : null;
                            const afterAds = offer ? Number(offer.after_ads) || 0 : (Number(plan.double_profit_after_ads) || 0);
                            const fee = offer ? Number(offer.fee) || 0 : (Number(plan.double_profit_fee) || 0);
                            const bonusPct = offer ? Number(offer.bonus_pct) || 0 : (Number(plan.double_profit_bonus_pct) || 0);
                            if (afterAds <= 0 || fee <= 0 || bonusPct <= 0) return res.status(400).json({ error: 'Double profit not available' });
                            if (used !== afterAds) return res.status(400).json({ error: 'Not eligible yet' });

                            db.get(
                                "SELECT id, payment_status FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND offer_after_ads = ? AND used_at IS NULL AND created_at >= ? ORDER BY id DESC LIMIT 1",
                                [userId, user.plan_id, afterAds, start],
                                (xErr, existing) => {
                                    if (xErr) return res.status(500).json({ error: 'DB Error' });
                                    if (existing) {
                                        const st = existing.payment_status ? String(existing.payment_status).toLowerCase() : 'paid';
                                        if (st === 'paid') return res.json({ success: true });
                                    }

                                    db.get("SELECT id, name, min_amount, max_amount, status FROM payment_methods WHERE id = ? AND status = 'active' LIMIT 1", [methodId], (mErr, method) => {
                                        if (mErr || !method) return res.status(400).json({ error: 'Invalid payment method' });
                                        const minAmount = Number(method.min_amount) || 0;
                                        const maxAmount = Number(method.max_amount) || 0;
                                        if (minAmount > 0 && fee < minAmount) return res.status(400).json({ error: `Amount must be at least ${minAmount}` });
                                        if (maxAmount > 0 && fee > maxAmount) return res.status(400).json({ error: `Amount must be at most ${maxAmount}` });

                                        const transactionId = `DP-${user.plan_id}-${afterAds}-${Date.now()}-${userId}`;
                                        const gateway = `Manual Double Profit (${method.name})`;
                                        const nowIso = new Date().toISOString();

                                        db.serialize(() => {
                                            db.run("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)", [userId, fee, gateway, transactionId, 'pending', nowIso, proofImage]);
                                            db.run(
                                                "INSERT INTO double_profit_offer_purchases (user_id, plan_id, ad_id, offer_id, offer_after_ads, fee, bonus_pct, out_order_number, payment_status, paid_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                                                [userId, user.plan_id, adId, offerId, afterAds, fee, bonusPct, transactionId, 'pending', nowIso],
                                                (iErr) => {
                                                    if (iErr) return res.status(500).json({ error: 'DB Error' });
                                                    res.json({ success: true, transaction_id: transactionId });
                                                }
                                            );
                                        });
                                    });
                                }
                            );
                        });
                    }
                );
            });
        });
    });
});

app.post('/api/admin/users/:id/double-profit-tasks/complete', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = Number(req.params.id);
    const offerId = req.body && req.body.offer_id !== undefined && req.body.offer_id !== null ? Number(req.body.offer_id) : null;
    if (!Number.isFinite(userId) || userId <= 0) return res.status(400).json({ error: 'Invalid user id' });
    if (!Number.isFinite(offerId) || offerId <= 0) return res.status(400).json({ error: 'Invalid offer_id' });

    db.get("SELECT id, plan_id, plan_expiry, plan_started_at FROM users WHERE id = ?", [userId], (uErr, user) => {
        if (uErr) return res.status(500).json({ error: 'DB Error' });
        if (!user || !user.plan_id || new Date(user.plan_expiry) < new Date()) {
            return res.status(400).json({ error: 'No active plan' });
        }

        db.get("SELECT id, duration FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
            if (pErr || !plan) return res.status(400).json({ error: 'Plan error' });

            db.get("SELECT id, plan_id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE id = ? AND plan_id = ? AND status = 'active' LIMIT 1", [offerId, user.plan_id], (oErr, offer) => {
                if (oErr) return res.status(500).json({ error: 'DB Error' });
                if (!offer) return res.status(404).json({ error: 'Offer not found' });

                const expiry = new Date(user.plan_expiry);
                const isValidExpiry = !isNaN(expiry.getTime());
                const durationDays = Number(plan.duration) || 0;

                const parseIso = (v) => {
                    const d = v ? new Date(v) : null;
                    return d && !isNaN(d.getTime()) ? d.toISOString() : null;
                };

                const fromUser = parseIso(user.plan_started_at);

                const inferFromExpiry = () => {
                    if (!isValidExpiry || durationDays <= 0) return null;
                    const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                    return start.toISOString();
                };

                const loadPlanStart = (cb) => {
                    if (fromUser) return cb(fromUser);
                    db.get(
                        "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                        [userId],
                        (sErr, sRow) => {
                            if (!sErr && sRow && sRow.created_at) {
                                const iso = parseIso(sRow.created_at);
                                if (iso) return cb(iso);
                            }
                            cb(inferFromExpiry());
                        }
                    );
                };

                loadPlanStart((startIso) => {
                    const start = startIso || inferFromExpiry() || new Date().toISOString();
                    db.get(
                        "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                        [userId, start],
                        (cErr, cRow) => {
                            if (cErr) return res.status(500).json({ error: 'DB Error' });
                            const watched = cRow && cRow.count ? Number(cRow.count) : 0;
                            const afterAds = Number(offer.after_ads) || 0;
                            if (watched > afterAds) return res.status(400).json({ error: 'User already passed this step' });

                            db.get(
                                "SELECT id FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND offer_after_ads = ? AND used_at IS NULL AND created_at >= ? LIMIT 1",
                                [userId, user.plan_id, afterAds, start],
                                (xErr, existing) => {
                                    if (xErr) return res.status(500).json({ error: 'DB Error' });
                                    if (existing) return res.json({ success: true });

                                    const nowIso = new Date().toISOString();
                                    db.run(
                                        "INSERT INTO double_profit_offer_purchases (user_id, plan_id, ad_id, offer_id, offer_after_ads, fee, bonus_pct, out_order_number, payment_status, paid_at, used_at, created_at) VALUES (?, ?, NULL, ?, ?, 0, ?, NULL, 'paid', ?, NULL, ?)",
                                        [userId, user.plan_id, offer.id, afterAds, Number(offer.bonus_pct) || 0, nowIso, nowIso],
                                        (iErr) => {
                                            if (iErr) return res.status(500).json({ error: 'DB Error' });
                                            res.json({ success: true });
                                        }
                                    );
                                }
                            );
                        }
                    );
                });
            });
        });
    });
});

// Admin API: Reset User Ads
app.post('/api/admin/users/:id/reset-ads', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = Number(req.params.id);
    if (!Number.isFinite(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid user id' });
    }

    db.serialize(() => {
        db.run('BEGIN TRANSACTION');

        db.get(
            "SELECT COALESCE(SUM(amount), 0) AS total, COUNT(*) AS cnt FROM deposits WHERE user_id = ? AND gateway = 'Ad View'",
            [userId],
            (sErr, sRow) => {
                if (sErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                const total = sRow && sRow.total !== undefined && sRow.total !== null ? Number(sRow.total) || 0 : 0;
                const cnt = sRow && sRow.cnt !== undefined && sRow.cnt !== null ? Number(sRow.cnt) || 0 : 0;

                db.run(
                    "UPDATE users SET balance = CASE WHEN balance - ? < 0 THEN 0 ELSE balance - ? END WHERE id = ?",
                    [total, total, userId],
                    (uErr) => {
                        if (uErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                        db.run("DELETE FROM deposits WHERE user_id = ? AND gateway = 'Ad View'", [userId], (dErr) => {
                            if (dErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                            db.run("DELETE FROM double_profit_offer_purchases WHERE user_id = ?", [userId], (dpErr) => {
                                if (dpErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                                db.run("DELETE FROM payment_orders WHERE user_id = ? AND order_type = 'double_profit'", [userId], (poErr) => {
                                    if (poErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                                    db.run(
                                        "UPDATE users SET plan_ads_used = 0, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ?",
                                        [userId],
                                        (rErr) => {
                                            if (rErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                                            db.get("SELECT balance FROM users WHERE id = ?", [userId], (fErr, uRow) => {
                                                if (fErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));

                                                db.run('COMMIT', (cErr) => {
                                                    if (cErr) return db.run('ROLLBACK', () => res.status(500).json({ error: 'DB Error' }));
                                                    res.json({
                                                        success: true,
                                                        count: cnt,
                                                        deducted: total,
                                                        newBalance: uRow ? uRow.balance : 0
                                                    });
                                                });
                                            });
                                        }
                                    );
                                });
                            });
                        });
                    }
                );
            }
        );
    });
});

// Admin API: Update User Details
app.put('/api/admin/users/:id', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { firstname, lastname, email, phone, country, city, zip, address, gender, dob, withdrawal_error_active, withdrawal_error_text, double_profit_disabled, is_banned } = req.body;
    const dpDisabled = double_profit_disabled === undefined ? null : (Number(double_profit_disabled) ? 1 : 0);
    const isBanned = is_banned === undefined ? null : (Number(is_banned) ? 1 : 0);
    
    const stmt = db.prepare(`
        UPDATE users 
        SET firstname = ?, lastname = ?, email = ?, phone = ?, country = ?, city = ?, zip = ?, address = ?, gender = ?, dob = ?, withdrawal_error_active = ?, withdrawal_error_text = ?, double_profit_disabled = COALESCE(?, double_profit_disabled), is_banned = COALESCE(?, is_banned) 
        WHERE id = ?
    `);
    
    stmt.run(firstname, lastname, email, phone, country, city, zip, address, gender, dob, withdrawal_error_active, withdrawal_error_text, dpDisabled, isBanned, req.params.id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

// Admin API: Change User Password
app.post('/api/admin/users/:id/password', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    db.run("UPDATE users SET password = ? WHERE id = ?", [password, req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Admin API: Send Referral Bonus (Manual)
app.post('/api/admin/users/:id/bonus', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { amount, reason } = req.body;
    const userId = req.params.id;
    const amountVal = parseFloat(amount);
    
    if (isNaN(amountVal) || amountVal <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

    // Add balance to user's REWARD BALANCE
    db.run("UPDATE users SET reward_balance = reward_balance + ? WHERE id = ?", [amountVal, userId], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        
        // Log transaction
        const trxId = `BONUS-${userId}-${Date.now()}`;
        const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, 'completed', ?)");
        // Use 'Referral Bonus' as gateway for rewards
        stmt.run(userId, amountVal, 'Referral Bonus', trxId, new Date().toISOString(), function(err) {
            if (err) console.error("Error logging bonus:", err);
            res.json({ success: true });
        });
        stmt.finalize();
    });
});

// Admin API: Login as User
app.post('/api/admin/login-as-user', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { userId } = req.body;
    db.get("SELECT * FROM users WHERE id = ?", [userId], (err, row) => {
        if (err || !row) return res.status(404).json({ error: 'User not found' });
        if (Number(row.is_banned) === 1) return res.status(400).json({ error: 'User is banned' });
        
        // Store admin ID to switch back later
        const adminId = req.session.user.id;
        req.session.user = row; 
        req.session.adminId = adminId;
        
        res.json({ success: true });
    });
});

// User API: Switch back to Admin
app.post('/api/switch-to-admin', (req, res) => {
    if (!req.session.adminId) {
        return res.status(403).json({ error: 'No admin session found' });
    }

    db.get("SELECT * FROM users WHERE id = ?", [req.session.adminId], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Admin user not found' });
        
        req.session.user = row;
        delete req.session.adminId;
        res.json({ success: true });
    });
});

// Admin API: Manage Balance
app.post('/api/admin/manage-balance', bodyParser.json(), (req, res) => {
    // Explicitly check for admin role and session existence
    if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
        console.log("Unauthorized balance attempt:", req.session);
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    // Manual session save to prevent race conditions or loss
    req.session.save((err) => {
        if (err) console.error("Session save error before balance update:", err);
        
        const { userId, amount, action } = req.body;
        
        // Ensure amount is a number
        const amountVal = parseFloat(amount);
        if (isNaN(amountVal) || amountVal <= 0) {
            return res.status(400).json({ error: 'Invalid amount' });
        }

        console.log(`Admin managing balance: User ${userId}, Action ${action}, Amount ${amountVal}`);

        let sql;
        if (action === 'add') {
            sql = "UPDATE users SET balance = balance + ? WHERE id = ?";
        } else if (action === 'subtract') {
            sql = "UPDATE users SET balance = balance - ? WHERE id = ?";
        } else {
            return res.status(400).json({ error: 'Invalid action' });
        }

        db.run(sql, [amountVal, userId], function(err) {
            if (err) {
                console.error("DB Error updating balance:", err);
                return res.status(500).json({ error: 'DB Error' });
            }
            
            // Log the new balance for verification
        db.get("SELECT balance FROM users WHERE id = ?", [userId], (err, row) => {
            if (row) {
                console.log(`Updated balance for user ${userId}: ${row.balance}`);
            }
            res.json({ success: true, newBalance: row ? row.balance : 0 }); // Send new balance back
        });
        });
    });
});

// Admin API: Activate subscription plan from user's wallet balance
app.post('/api/admin/users/:id/activate-plan-wallet', bodyParser.json(), (req, res) => {
    if (!req.session || !req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = Number(req.params.id);
    const planId = Number(req.body.plan_id);

    if (!Number.isFinite(userId) || userId <= 0) {
        return res.status(400).json({ error: 'Invalid user id' });
    }
    if (!Number.isFinite(planId) || planId <= 0) {
        return res.status(400).json({ error: 'Invalid plan id' });
    }

    db.get("SELECT id, price, duration, daily_limit FROM plans WHERE id = ? AND status = 'active'", [planId], (pErr, plan) => {
        if (pErr) return res.status(500).json({ error: 'DB Error' });
        if (!plan) return res.status(404).json({ error: 'Plan not found' });

        const planPrice = Number(plan.price) || 0;
        const planDuration = Number(plan.duration) || 0;
        if (planPrice <= 0 || planDuration <= 0) {
            return res.status(400).json({ error: 'Invalid plan configuration' });
        }

        db.get("SELECT id, balance, plan_id, plan_expiry FROM users WHERE id = ?", [userId], (uErr, user) => {
            if (uErr) return res.status(500).json({ error: 'DB Error' });
            if (!user) return res.status(404).json({ error: 'User not found' });

            const now = new Date();
            let expiryBase = now;
            if (Number(user.plan_id) === planId && user.plan_expiry) {
                const currentExpiry = new Date(user.plan_expiry);
                if (!isNaN(currentExpiry.getTime()) && currentExpiry > now) {
                    expiryBase = currentExpiry;
                }
            }
            const newExpiry = new Date(expiryBase.getTime() + planDuration * 24 * 60 * 60 * 1000).toISOString();

            const transactionId = `SUB-${planId}-${Date.now()}-${userId}`;
            const createdAt = new Date().toISOString();
            const totalAds = Number(plan.daily_limit) || 0;

            const rollback = (status, payload) => {
                db.run('ROLLBACK', () => res.status(status).json(payload));
            };

            db.serialize(() => {
                db.run('BEGIN TRANSACTION');

                db.run(
                    "UPDATE users SET balance = balance - ?, plan_id = ?, plan_expiry = ?, plan_started_at = ?, plan_ads_used = 0, plan_ads_total = ?, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ? AND balance >= ?",
                    [planPrice, planId, newExpiry, createdAt, totalAds, userId, planPrice],
                    function (upErr) {
                        if (upErr) return rollback(500, { error: 'DB Error' });
                        if (!this.changes) return rollback(400, { error: 'Insufficient balance' });

                        db.run(
                            "INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                            [userId, planPrice, 'Wallet Subscription', transactionId, 'approved', createdAt],
                            (dErr) => {
                                if (dErr) return rollback(500, { error: 'DB Error' });

                                db.get("SELECT balance, plan_id, plan_expiry FROM users WHERE id = ?", [userId], (fErr, updated) => {
                                    if (fErr) return rollback(500, { error: 'DB Error' });

                                    db.run('COMMIT', (cErr) => {
                                        if (cErr) return rollback(500, { error: 'DB Error' });
                                        res.json({
                                            success: true,
                                            newBalance: updated ? updated.balance : undefined,
                                            plan_id: updated ? updated.plan_id : planId,
                                            plan_expiry: updated ? updated.plan_expiry : newExpiry
                                        });
                                    });
                                });
                            }
                        );
                    }
                );
            });
        });
    });
});

// Admin API: Delete User
app.delete('/api/admin/users/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.run("DELETE FROM users WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Admin Routes
/* app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
}); */

app.post('/register', (req, res) => {
    const { firstname, lastname, username, email, country, phone, referral, gender, password } = req.body;
    
    // Simple validation
    if (!username || !email || !phone || !password) {
        return res.status(400).json({ error: 'Please fill in all required fields' });
    }

    const cleanUsername = String(username || '').trim();
    const cleanEmail = String(email || '').trim();
    const cleanPhoneDigits = String(phone || '').replace(/\D/g, '');

    if (!cleanUsername || !cleanEmail || !cleanPhoneDigits || !password) {
        return res.status(400).json({ error: 'Please fill in all required fields' });
    }

    db.get(
        "SELECT id, username, email, phone FROM users WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?) OR phone = ? LIMIT 1",
        [cleanEmail, cleanUsername, cleanPhoneDigits],
        (cErr, existing) => {
            if (cErr) return res.status(500).json({ error: 'Database error' });
            if (existing) {
                const existingEmail = existing.email ? String(existing.email).trim() : '';
                const existingUsername = existing.username ? String(existing.username).trim() : '';
                const existingPhone = existing.phone ? String(existing.phone).replace(/\D/g, '') : '';
                const emailMatch = existingEmail && existingEmail.toLowerCase() === cleanEmail.toLowerCase();
                const usernameMatch = existingUsername && existingUsername.toLowerCase() === cleanUsername.toLowerCase();
                const phoneMatch = existingPhone && existingPhone === cleanPhoneDigits;
                if (emailMatch) return res.status(400).json({ error: 'Email already exists' });
                if (usernameMatch) return res.status(400).json({ error: 'Username already exists' });
                if (phoneMatch) return res.status(400).json({ error: 'Phone number already exists' });
                return res.status(400).json({ error: 'Email/username/phone already exists' });
            }

            const stmt = db.prepare("INSERT INTO users (firstname, lastname, username, email, country, phone, referral, gender, password, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            const created_at = new Date().toISOString();
            stmt.run(
                firstname,
                lastname,
                cleanUsername,
                cleanEmail,
                country,
                cleanPhoneDigits,
                referral,
                gender,
                password,
                created_at,
                function(err) {
                    if (err) {
                        console.error(err);
                        return res.status(500).json({ error: 'Database error' });
                    }
                    
                    const newUserId = this.lastID;

                    db.get("SELECT value FROM settings WHERE key = 'joining_bonus'", (err, row) => {
                        const joiningBonus = !err && row && row.value !== undefined && row.value !== null ? Number(row.value) || 0 : 0;

                        const finish = (finalBalance) => {
                            // --- REFERRAL SIGNUP BONUS LOGIC ---
                            // Only if referral code was provided
                            if (referral && referral.trim() !== '') {
                                db.get("SELECT value FROM settings WHERE key = 'referral_signup_bonus'", (err, row) => {
                                    if (!err && row) {
                                        const bonus = parseFloat(row.value);
                                        if (bonus > 0) {
                                            const referralCode = referral.trim();
                                            db.get("SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)", [referralCode], (e3, refUser) => {
                                                if (e3 || !refUser) return;
                                                if (Number(refUser.id) === Number(newUserId)) return;

                                                db.run("UPDATE users SET reward_balance = reward_balance + ? WHERE id = ?", [bonus, refUser.id], (e4) => {
                                                    if (e4) return;
                                                    const trxId = `REFERRAL-BONUS-${refUser.id}-${newUserId}-${Date.now()}`;
                                                    const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
                                                    stmt.run(refUser.id, bonus, 'Referral Bonus', trxId, 'completed', new Date().toISOString());
                                                    stmt.finalize();
                                                    console.log(`Referral Bonus of ${bonus} awarded to referrer ${refUser.username} for new user ${cleanUsername}`);
                                                });
                                            });
                                        }
                                    }
                                });
                            }
                            // -----------------------------------

                            req.session.user = { id: newUserId, username: cleanUsername, email: cleanEmail, firstname, lastname, country, phone: cleanPhoneDigits, referral, gender, created_at, role: 'user', balance: finalBalance };
                            res.json({ success: true, redirect: '/dashboard.html' });
                        };

                        if (joiningBonus > 0) {
                            db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [joiningBonus, newUserId], () => {
                                finish(joiningBonus);
                            });
                        } else {
                            finish(0.0);
                        }
                    });
                }
            );
            stmt.finalize();
        }
    );
});


// User API: Submit KYC (Disabled)
/* app.post('/api/user/kyc', upload.single('photo'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { name, details } = req.body;
    const photo_path = req.file ? '/uploads/' + req.file.filename : null;

    const stmt = db.prepare("INSERT INTO kyc_requests (user_id, name, details, photo_path, created_at) VALUES (?, ?, ?, ?, ?)");
    stmt.run(req.session.user.id, name, details, photo_path, new Date().toISOString(), function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'DB Error' });
        }
        res.json({ success: true });
    });
    stmt.finalize();
}); */

// User API: Get KYC History (Disabled)
/* app.get('/api/user/kyc-history', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM kyc_requests WHERE user_id = ? ORDER BY id DESC", [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
}); */

// Admin API: Get General Settings
app.get('/api/admin/settings/general', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    db.all("SELECT key, value FROM settings", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        
        const settings = {};
        rows.forEach(row => {
            settings[row.key] = row.value;
        });
        res.json(settings);
    });
});

app.get('/api/settings/general', (req, res) => {
    db.all("SELECT key, value FROM settings WHERE key IN ('site_name','currency_symbol','referral_signup_bonus','joining_bonus')", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        const settings = { site_name: 'RewardLoop', currency_symbol: 'PKR', referral_signup_bonus: 0, joining_bonus: 0 };
        rows.forEach(row => {
            if (row.key === 'referral_signup_bonus') settings[row.key] = Number(row.value) || 0;
            else if (row.key === 'joining_bonus') settings[row.key] = Number(row.value) || 0;
            else settings[row.key] = row.value;
        });
        res.json(settings);
    });
});

app.get('/api/settings/community', (req, res) => {
    db.all("SELECT key, value FROM settings WHERE key IN ('community_enabled','community_group_url','community_fake_chat_enabled','community_fake_user_count','community_message_interval_ms')", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        const settings = {
            community_enabled: '1',
            community_group_url: '',
            community_fake_chat_enabled: '1',
            community_fake_user_count: '400',
            community_message_interval_ms: '1100'
        };
        rows.forEach(row => {
            settings[row.key] = row.value;
        });
        res.json(settings);
    });
});

app.get('/api/community/status', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    db.get("SELECT username, community_joined, community_joined_at FROM users WHERE id = ? LIMIT 1", [req.session.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({
            user_id: req.session.user.id,
            username: row && row.username ? String(row.username) : '',
            joined: row && Number(row.community_joined) === 1,
            joined_at: row && row.community_joined_at ? String(row.community_joined_at) : null
        });
    });
});

app.post('/api/community/join', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const now = new Date().toISOString();
    db.run("UPDATE users SET community_joined = 1, community_joined_at = ? WHERE id = ?", [now, req.session.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, joined_at: now });
    });
});

app.get('/api/community/messages', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const limit = req.query && req.query.limit !== undefined && req.query.limit !== null ? Number(req.query.limit) : 60;
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(200, Math.floor(limit))) : 60;
    const afterId = req.query && req.query.after_id !== undefined && req.query.after_id !== null ? Number(req.query.after_id) : 0;
    const safeAfter = Number.isFinite(afterId) ? Math.max(0, Math.floor(afterId)) : 0;
    const params = safeAfter > 0 ? [safeAfter, safeLimit] : [safeLimit];
    const sql = safeAfter > 0
        ? "SELECT id, sender_type, sender_name, message, reply_to, media_url, media_kind, media_name, created_at FROM community_messages WHERE id > ? ORDER BY id ASC LIMIT ?"
        : "SELECT id, sender_type, sender_name, message, reply_to, media_url, media_kind, media_name, created_at FROM community_messages ORDER BY id DESC LIMIT ?";
    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        const out = safeAfter > 0 ? (rows || []) : (rows || []).slice().reverse();
        res.json({ messages: out });
    });
});

app.post('/api/community/messages', bodyParser.json(), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const message = req.body && req.body.message !== undefined && req.body.message !== null ? String(req.body.message).trim() : '';
    const replyTo = req.body && req.body.reply_to !== undefined && req.body.reply_to !== null ? String(req.body.reply_to).trim() : '';
    if (!message) return res.status(400).json({ error: 'Message is required' });
    if (message.length > 600) return res.status(400).json({ error: 'Message too long' });
    const now = new Date().toISOString();
    db.get("SELECT username FROM users WHERE id = ? LIMIT 1", [req.session.user.id], (e1, u) => {
        const senderName = u && u.username ? String(u.username) : 'User';
        db.run(
            "INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, media_url, media_kind, media_name, created_at) VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL, ?)",
            ['user', req.session.user.id, senderName, message, replyTo || null, now],
            function (e2) {
                if (e2) return res.status(500).json({ error: 'DB Error' });
                res.json({ success: true, message: { id: this.lastID, sender_type: 'user', sender_name: senderName, message, reply_to: replyTo || null, media_url: null, media_kind: null, media_name: null, created_at: now } });
            }
        );
    });
});

app.post('/api/community/messages/media', communityUpload.single('media'), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const message = req.body && req.body.message !== undefined && req.body.message !== null ? String(req.body.message).trim() : '';
    const replyTo = req.body && req.body.reply_to !== undefined && req.body.reply_to !== null ? String(req.body.reply_to).trim() : '';
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Media is required' });
    if (message.length > 600) return res.status(400).json({ error: 'Message too long' });
    const t = (file.mimetype ? String(file.mimetype) : '').toLowerCase();
    const kind = t.startsWith('video/') ? 'video' : 'image';
    const mediaUrl = '/uploads/' + file.filename;
    const mediaName = file.originalname ? String(file.originalname) : '';
    const now = new Date().toISOString();
    db.get("SELECT username FROM users WHERE id = ? LIMIT 1", [req.session.user.id], (e1, u) => {
        const senderName = u && u.username ? String(u.username) : 'User';
        db.run(
            "INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, media_url, media_kind, media_name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ['user', req.session.user.id, senderName, message, replyTo || null, mediaUrl, kind, mediaName || null, now],
            function (e2) {
                if (e2) return res.status(500).json({ error: 'DB Error' });
                res.json({ success: true, message: { id: this.lastID, sender_type: 'user', sender_name: senderName, message, reply_to: replyTo || null, media_url: mediaUrl, media_kind: kind, media_name: mediaName || null, created_at: now } });
            }
        );
    });
});

app.get('/api/admin/community/messages', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const limit = req.query && req.query.limit !== undefined && req.query.limit !== null ? Number(req.query.limit) : 200;
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(500, Math.floor(limit))) : 200;
    db.all("SELECT id, sender_type, sender_name, message, reply_to, media_url, media_kind, media_name, created_at FROM community_messages ORDER BY id DESC LIMIT ?", [safeLimit], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ messages: (rows || []).slice().reverse() });
    });
});

app.get('/api/admin/community/joined-users', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const limit = req.query && req.query.limit !== undefined && req.query.limit !== null ? Number(req.query.limit) : 200;
    const safeLimit = Number.isFinite(limit) ? Math.max(1, Math.min(500, Math.floor(limit))) : 200;
    const q = req.query && req.query.q !== undefined && req.query.q !== null ? String(req.query.q).trim() : '';
    const like = q ? `%${q.toLowerCase()}%` : '';
    const where = q ? "WHERE community_joined = 1 AND (LOWER(username) LIKE ? OR LOWER(email) LIKE ?)" : "WHERE community_joined = 1";
    const params = q ? [like, like] : [];

    db.get(`SELECT COUNT(*) as c FROM users ${where}`, params, (cErr, cRow) => {
        if (cErr) return res.status(500).json({ error: 'DB Error' });
        db.all(
            `SELECT id, username, email, community_joined, community_joined_at, created_at FROM users ${where} ORDER BY community_joined_at DESC, id DESC LIMIT ?`,
            params.concat([safeLimit]),
            (err, rows) => {
                if (err) return res.status(500).json({ error: 'DB Error' });
                res.json({ total: cRow && cRow.c ? Number(cRow.c) : 0, users: rows || [] });
            }
        );
    });
});

app.post('/api/admin/community/post', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const message = req.body && req.body.message !== undefined && req.body.message !== null ? String(req.body.message).trim() : '';
    const senderTypeRaw = req.body && req.body.sender_type !== undefined && req.body.sender_type !== null ? String(req.body.sender_type).trim().toLowerCase() : 'admin';
    const senderType = senderTypeRaw === 'fake' ? 'fake' : 'admin';
    const senderNameRaw = req.body && req.body.sender_name !== undefined && req.body.sender_name !== null ? String(req.body.sender_name).trim() : '';
    const replyTo = req.body && req.body.reply_to !== undefined && req.body.reply_to !== null ? String(req.body.reply_to).trim() : '';
    if (!message) return res.status(400).json({ error: 'Message is required' });
    if (message.length > 600) return res.status(400).json({ error: 'Message too long' });
    let senderName = senderType === 'admin' ? 'Admin' : senderNameRaw;
    if (senderType === 'fake' && !senderName) return res.status(400).json({ error: 'Fake sender name is required' });
    if (senderName.length > 40) senderName = senderName.slice(0, 40);
    const now = new Date().toISOString();
    db.run(
        "INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, media_url, media_kind, media_name, created_at) VALUES (?, NULL, ?, ?, ?, NULL, NULL, NULL, ?)",
        [senderType, senderName, message, replyTo || null, now],
        function (e2) {
            if (e2) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, message: { id: this.lastID, sender_type: senderType, sender_name: senderName, message, reply_to: replyTo || null, media_url: null, media_kind: null, media_name: null, created_at: now } });
        }
    );
});

app.post('/api/admin/community/post-media', communityUpload.single('media'), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const message = req.body && req.body.message !== undefined && req.body.message !== null ? String(req.body.message).trim() : '';
    const senderTypeRaw = req.body && req.body.sender_type !== undefined && req.body.sender_type !== null ? String(req.body.sender_type).trim().toLowerCase() : 'admin';
    const senderType = senderTypeRaw === 'fake' ? 'fake' : 'admin';
    const senderNameRaw = req.body && req.body.sender_name !== undefined && req.body.sender_name !== null ? String(req.body.sender_name).trim() : '';
    const replyTo = req.body && req.body.reply_to !== undefined && req.body.reply_to !== null ? String(req.body.reply_to).trim() : '';
    const file = req.file;
    if (!file) return res.status(400).json({ error: 'Media is required' });
    if (message.length > 600) return res.status(400).json({ error: 'Message too long' });
    let senderName = senderType === 'admin' ? 'Admin' : senderNameRaw;
    if (senderType === 'fake' && !senderName) return res.status(400).json({ error: 'Fake sender name is required' });
    if (senderName.length > 40) senderName = senderName.slice(0, 40);
    const t = (file.mimetype ? String(file.mimetype) : '').toLowerCase();
    const kind = t.startsWith('video/') ? 'video' : 'image';
    const mediaUrl = '/uploads/' + file.filename;
    const mediaName = file.originalname ? String(file.originalname) : '';
    const now = new Date().toISOString();
    db.run(
        "INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, media_url, media_kind, media_name, created_at) VALUES (?, NULL, ?, ?, ?, ?, ?, ?, ?)",
        [senderType, senderName, message, replyTo || null, mediaUrl, kind, mediaName || null, now],
        function (e2) {
            if (e2) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, message: { id: this.lastID, sender_type: senderType, sender_name: senderName, message, reply_to: replyTo || null, media_url: mediaUrl, media_kind: kind, media_name: mediaName || null, created_at: now } });
        }
    );
});

app.post('/api/admin/community/generate-fake', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    const countRaw = req.body && req.body.count !== undefined && req.body.count !== null ? Number(req.body.count) : 0;
    const count = Number.isFinite(countRaw) ? Math.max(1, Math.min(5000, Math.floor(countRaw))) : 0;
    if (!count) return res.status(400).json({ error: 'Invalid count' });

    const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
    const first = ['Ali','Ahmed','Ayesha','Fatima','Zain','Hassan','Hamza','Sara','Umar','Bilal','Maryam','Noor','Hina','Asad','Usman','Musa','Kiran','Iqra','Saad','Daniyal','Rida','Sana','Haris','Farhan','Amna','Anaya','Zoya','Areeba','Aqsa','Huzaifa'];
    const last = ['Khan','Malik','Sheikh','Butt','Raza','Iqbal','Hussain','Chaudhry','Siddiqui','Qureshi','Javed','Nawaz','Rashid','Mirza','Yousaf','Saleem','Haq','Shah','Ansari','Bhatti','Rehman','Akhtar','Abbasi','Kashif','Rafiq','Aziz','Junaid','Noman','Haider','Mehmood'];
    const templates = [
        'Anyone got today’s ads completed?',
        'Just withdrew successfully, thanks!',
        'What plan are you using right now?',
        'Good morning everyone!',
        'I upgraded my plan and earnings improved.',
        'Support replied fast today.',
        'Don’t forget to check rewards tab.',
        'My ads page is loading slow for me, anyone else?',
        'Referral bonus just received.',
        'Keep going, consistency matters.',
        'What’s your target for this week?',
        'Congrats on your withdrawal!',
        'Remember to submit proof correctly.',
        'Which wallet do you use for PKR?',
        'I just joined, nice to meet you all.',
        'Any tips for new users?',
        'Stay active and complete daily tasks.',
        'Let’s help each other.',
        'How many ads per day on VIP?',
        'Best time to do ads?',
        'I like the new updates.',
        'Please be careful with scammers.',
        'Always use official links.',
        'Anyone from Karachi here?',
        'Pakistan community is strong!',
        'Let’s share progress.',
        'Today’s earnings: decent.',
        'Keep the chat clean.',
        'I’m waiting for my plan activation.',
        'Admin will approve soon, be patient.'
    ];

    db.all("SELECT message FROM community_messages WHERE sender_type = 'fake' ORDER BY id DESC LIMIT 300", (rErr, rows) => {
        const recent = new Set((rows || []).map(r => (r && r.message ? String(r.message).trim() : '')).filter(Boolean));
        const usedInBatch = new Set();
        const genMessage = () => {
            let msg = String(pick(templates) || '').trim();
            if (!msg) msg = 'Hello everyone!';
            if (msg.toLowerCase().includes('what plan')) msg = `What plan are you using right now? ${pick(plans)}`;
            if (msg.includes('VIP')) msg = msg.replaceAll('VIP', pick(plans));
            if (msg.toLowerCase().includes('withdraw')) msg = `${msg} (PKR ${Math.floor(Math.random() * 900 + 100)})`;
            if (msg.toLowerCase().includes('ads')) msg = `${msg} (${Math.floor(Math.random() * 9 + 1)} ads)`;
            if (Math.random() < 0.55) msg = `${msg} ${pick(suffixes)}`;
            return msg.trim();
        };
        const pickFresh = () => {
            for (let i = 0; i < 25; i++) {
                const key = genMessage();
                if (!key) continue;
                if (recent.has(key)) continue;
                if (usedInBatch.has(key)) continue;
                usedInBatch.add(key);
                return key;
            }
            const key = genMessage();
            usedInBatch.add(key);
            return key;
        };

        const now = new Date().toISOString();
        const stmt = db.prepare("INSERT INTO community_messages (sender_type, sender_user_id, sender_name, message, reply_to, media_url, media_kind, media_name, created_at) VALUES ('fake', NULL, ?, ?, NULL, NULL, NULL, NULL, ?)");
        for (let i = 0; i < count; i++) {
            const senderName = `${pick(first)} ${pick(last)} ${String(Math.floor(Math.random() * 90) + 10)}`;
            const msg = pickFresh();
            stmt.run(senderName, msg, now);
        }
        stmt.finalize((e) => {
            if (e) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, inserted: count });
        });
    });
});

app.get('/api/withdraw/methods', (req, res) => {
    const map = {
        PKR: [
            { label: 'Mobile Wallets', options: ['JazzCash', 'EasyPaisa', 'Nayapay', 'Sadapay'] },
            { label: 'Banks', options: ['HBL (Habib Bank Limited)', 'UBL (United Bank Limited)', 'Meezan Bank', 'Bank Alfalah', 'Allied Bank', 'MCB Bank', 'Askari Bank', 'Faysal Bank', 'Bank of Punjab', 'Standard Chartered'] }
        ],
        INR: [
            { label: 'Digital Payments', options: ['UPI', 'Paytm', 'PhonePe', 'Google Pay'] },
            { label: 'Bank Transfer', options: ['IMPS', 'NEFT', 'RTGS'] },
            { label: 'Banks', options: ['State Bank of India (SBI)', 'HDFC Bank', 'ICICI Bank', 'Axis Bank', 'Kotak Mahindra Bank', 'Punjab National Bank (PNB)'] }
        ],
        BRL: [
            { label: 'Instant Payments', options: ['PIX'] },
            { label: 'Banks', options: ['Nubank', 'Banco do Brasil', 'Caixa Econômica Federal', 'Itaú Unibanco', 'Bradesco', 'Santander Brasil', 'Banco Inter'] }
        ]
    };

    db.get("SELECT value FROM settings WHERE key = 'currency_symbol' LIMIT 1", (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        const currency = (row && row.value ? String(row.value) : 'PKR').trim() || 'PKR';
        const groups = map[currency] || map.PKR;
        res.json({ currency_symbol: currency, groups });
    });
});

function nicePaySign(params, key) {
    const keys = Object.keys(params || {}).filter(k => k !== 'sign' && params[k] !== '' && params[k] !== null && params[k] !== undefined && !Array.isArray(params[k]));
    keys.sort();
    const base = keys.map(k => `${k}=${params[k]}`).join('&');
    return crypto.createHash('md5').update(`${base}&key=${key}`).digest('hex').toUpperCase();
}

function nicePayAmountMatches(a, b) {
    const x = Number(a);
    const y = Number(b);
    if (!Number.isFinite(x) || !Number.isFinite(y)) return true;
    return Math.abs(x - y) < 0.0001;
}

function extractYouTubeIdFromUrl(url) {
    if (!url) return null;
    const s = String(url);
    const m = s.match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?v=|embed\/|v\/))([A-Za-z0-9_-]{11})/);
    return m && m[1] ? m[1] : null;
}

async function isYouTubeOEmbedOk(videoId) {
    try {
        const u = `https://www.youtube.com/oembed?url=${encodeURIComponent(`https://www.youtube.com/watch?v=${videoId}`)}&format=json`;
        const r = await fetch(u, { method: 'GET' });
        return !!(r && r.ok);
    } catch {
        return false;
    }
}

function auditAdsToDisableUnavailable() {
    if (typeof fetch !== 'function') return;
    db.all("SELECT id, url FROM ads WHERE status = 'active'", async (err, rows) => {
        if (err || !Array.isArray(rows) || rows.length === 0) return;
        const tasks = [];
        rows.forEach(r => {
            const vid = extractYouTubeIdFromUrl(r.url);
            if (!vid) return;
            tasks.push({ id: r.id, vid });
        });
        if (!tasks.length) return;

        for (let i = 0; i < tasks.length; i++) {
            const t = tasks[i];
            const ok = await isYouTubeOEmbedOk(t.vid);
            if (!ok) {
                db.run("UPDATE ads SET status = 'inactive' WHERE id = ?", [t.id]);
            }
        }

        const keepMinimumActiveAds = String(process.env.KEEP_MINIMUM_ACTIVE_ADS || '').trim() === '1';
        if (!keepMinimumActiveAds) return;

        db.get("SELECT COUNT(*) as count FROM ads WHERE status = 'active'", (cErr, cRow) => {
            if (cErr || !cRow) return;
            const current = Number(cRow.count) || 0;
            if (current >= 100) return;
            const needed = 100 - current;

            const videoTitles = [
                "Relaxing Nature 4K",
                "Funny Cats Compilation",
                "Cute Puppies Playing",
                "Yoga for Beginners",
                "Meditation Music",
                "Science Documentary: Space",
                "History Documentary",
                "Learn JavaScript Basics",
                "Tech Review",
                "Travel Vlog",
                "Street Food Tour",
                "DIY Home Decor",
                "Fitness Workout Routine",
                "Cooking Recipe",
                "Motivational Speech"
            ];

            const youtubeIds = [
                "hY7m5jjJ9mM",
                "v7AYKMP6rOE",
                "U9BwWKXjVaI",
                "ScMzIvxBSi4",
                "WpTdAogP70M",
                "j5-yKhDd64s",
                "UnZWTuDDpKs",
                "34Na4j8AVgA",
                "7WTpNHjFNZM",
                "lTRiuFIWV54",
                "tgbNymZ7vqY",
                "PT2_F-1esPk",
                "0KSOMA3QBU0",
                "kJQP7kiw5Fk",
                "OPf0YbXqDm0"
            ];

            const rand = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;
            const randReward = () => (Math.random() * 4.5 + 0.5).toFixed(2);

            const stmt = db.prepare("INSERT INTO ads (title, url, duration, reward, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
            const now = new Date().toISOString();
            for (let i = 0; i < needed; i++) {
                const title = videoTitles[i % videoTitles.length];
                const vidId = youtubeIds[i % youtubeIds.length];
                stmt.run(title, `https://www.youtube.com/watch?v=${vidId}`, rand(10, 60), randReward(), 'active', now);
            }
            stmt.finalize();
        });
    });
}

function logNicePaySyncHistory(opts) {
    const outOrderNumber = (opts && opts.outOrderNumber ? String(opts.outOrderNumber) : '').trim();
    if (!outOrderNumber) return;

    const adminId = Number(opts && opts.adminId);
    const adminUsername = opts && opts.adminUsername ? String(opts.adminUsername) : '';
    const endpoint = opts && opts.endpoint ? String(opts.endpoint) : '';
    const result = opts && opts.result ? String(opts.result) : '';
    const responseCode = opts && opts.responseCode !== undefined && opts.responseCode !== null ? Number(opts.responseCode) : null;
    const responseStatus = opts && opts.responseStatus !== undefined && opts.responseStatus !== null ? String(opts.responseStatus) : '';
    const responseAmount = opts && opts.responseAmount !== undefined && opts.responseAmount !== null ? Number(opts.responseAmount) : null;
    const responseRealAmount = opts && opts.responseRealAmount !== undefined && opts.responseRealAmount !== null ? Number(opts.responseRealAmount) : null;
    const responseMsg = opts && opts.responseMsg ? String(opts.responseMsg) : '';
    const responseJson = opts && opts.responseJson ? String(opts.responseJson) : '';

    db.run(
        "INSERT INTO nicepay_sync_history (out_order_number, admin_id, admin_username, endpoint, result, response_code, response_status, response_amount, response_real_amount, response_msg, response_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            outOrderNumber,
            Number.isFinite(adminId) ? adminId : null,
            adminUsername,
            endpoint,
            result,
            Number.isFinite(responseCode) ? responseCode : null,
            responseStatus,
            Number.isFinite(responseAmount) ? responseAmount : null,
            Number.isFinite(responseRealAmount) ? responseRealAmount : null,
            responseMsg,
            responseJson,
            new Date().toISOString()
        ]
    );
}

function getRequestIp(req) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf && typeof cf === 'string' && cf.trim()) return cf.trim();
    const xr = req.headers['x-real-ip'];
    if (xr && typeof xr === 'string' && xr.trim()) return xr.trim();
    const xf = req.headers['x-forwarded-for'];
    if (xf && typeof xf === 'string') {
        const first = xf.split(',')[0].trim();
        if (first) return first;
    }
    if (req.ip) return String(req.ip).replace('::ffff:', '').trim();
    if (req.connection && req.connection.remoteAddress) return String(req.connection.remoteAddress).replace('::ffff:', '').trim();
    return '';
}

function isNicePayPaid(payload) {
    const v = (payload && (payload.status ?? payload.pay_status ?? payload.trade_status ?? payload.result ?? payload.result_status ?? payload.order_status)) ?? '';
    const s = String(v).trim().toLowerCase();
    if (['paid', 'success', 'successful', 'completed', '1', '2', '00', '0000', 'true', 'yes', 'ok'].includes(s)) return true;
    const rc = payload && (payload.result_code ?? payload.code ?? payload.resultCode);
    if (rc !== undefined && rc !== null) {
        const rcs = String(rc).trim().toLowerCase();
        if (['0', '00', '0000', 'success', 'ok'].includes(rcs)) return true;
    }
    return false;
}

function awardReferralDepositCommission(opts) {
    const referredUserId = Number(opts && opts.referredUserId);
    const depositAmount = Number(opts && opts.depositAmount);
    const sourceTransactionId = (opts && opts.sourceTransactionId ? String(opts.sourceTransactionId) : '').trim();

    if (!Number.isFinite(referredUserId) || referredUserId <= 0) return;
    if (!Number.isFinite(depositAmount) || depositAmount <= 0) return;
    if (!sourceTransactionId) return;

    if (sourceTransactionId.startsWith('SUB-')) return;
    if (sourceTransactionId.startsWith('AD-')) return;
    if (sourceTransactionId.startsWith('REFERRAL-') || sourceTransactionId.startsWith('REF-COMMISSION-')) return;
    if (sourceTransactionId.startsWith('REDEEM-')) return;

    db.get("SELECT value FROM settings WHERE key = 'referral_deposit_commission_pct' LIMIT 1", (sErr, sRow) => {
        const pctRaw = !sErr && sRow && sRow.value !== undefined && sRow.value !== null ? Number(sRow.value) : 10;
        const pct = Number.isFinite(pctRaw) ? Math.min(Math.max(pctRaw, 0), 100) : 10;
        if (pct <= 0) return;

        const commission = Math.round(((depositAmount * pct) / 100) * 100) / 100;
        if (!Number.isFinite(commission) || commission <= 0) return;

        db.get("SELECT referral FROM users WHERE id = ?", [referredUserId], (e1, u) => {
        if (e1 || !u || !u.referral) return;
        const referralCode = String(u.referral || '').trim();
        if (!referralCode) return;

        db.get("SELECT id, username FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1", [referralCode], (e2, refUser) => {
            if (e2 || !refUser) return;
            if (Number(refUser.id) === referredUserId) return;

            const trxId = `REF-COMMISSION-${refUser.id}-${referredUserId}-${sourceTransactionId}`;
            db.get("SELECT id FROM deposits WHERE transaction_id = ? LIMIT 1", [trxId], (e3, exists) => {
                if (!e3 && exists) return;

                db.run("UPDATE users SET reward_balance = reward_balance + ? WHERE id = ?", [commission, refUser.id], (e4) => {
                    if (e4) return;
                    const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
                    stmt.run(refUser.id, commission, 'Referral Commission', trxId, 'completed', new Date().toISOString());
                    stmt.finalize();
                });
            });
        });
        });
    });
}

app.post('/api/nicepay/subscription/create', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const planId = Number(req.body.plan_id);
    if (!Number.isFinite(planId) || planId <= 0) return res.status(400).json({ error: 'Invalid plan_id' });

    const merchantId = (process.env.NICEPAY_MERCHANT_ID || '').trim();
    const gateId = (process.env.NICEPAY_GATE_ID || '').trim();
    const key = (process.env.NICEPAY_KEY || '').trim();
    const orderApiUrl = (process.env.NICEPAY_ORDER_API_URL || '').trim();
    const appBaseUrl = (process.env.APP_BASE_URL || '').trim();

    if (!merchantId || !gateId || !key || !orderApiUrl) {
        return res.status(500).json({ error: 'NicePay not configured' });
    }

    const notifyUrl = (process.env.NICEPAY_NOTIFY_URL || (appBaseUrl ? `${appBaseUrl.replace(/\/+$/, '')}/api/nicepay/notify` : '')).trim();
    if (!notifyUrl) return res.status(500).json({ error: 'NicePay notify_url not configured' });

    db.get("SELECT * FROM plans WHERE id = ? AND status = 'active'", [planId], async (err, plan) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!plan) return res.status(404).json({ error: 'Plan not found' });

        const outOrderNumber = `SUB-${planId}-${Date.now()}-${req.session.user.id}`;
        const amount = String(plan.price);

        const params = {
            out_order_number: outOrderNumber,
            amount,
            merchant_id: merchantId,
            gate_id: gateId,
            notify_url: notifyUrl
        };
        const sign = nicePaySign(params, key);
        const payload = { ...params, sign };

        try {
            const apiRes = await fetch(orderApiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await apiRes.json().catch(() => ({}));
            if (!apiRes.ok) return res.status(502).json({ error: 'NicePay create order failed', details: data });
            if (!data || data.code !== 0) return res.status(502).json({ error: data && data.msg ? String(data.msg) : 'NicePay create order failed', details: data });
            const payUrl = data && data.data && data.data.pay_url ? String(data.data.pay_url) : '';
            if (!payUrl) return res.status(502).json({ error: 'NicePay pay_url missing', details: data });

            db.run(
                "INSERT OR IGNORE INTO payment_orders (provider, out_order_number, user_id, order_type, plan_id, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ['nicepay', outOrderNumber, req.session.user.id, 'subscription', planId, plan.price, 'pending', new Date().toISOString()],
                () => {
                    res.json({ success: true, out_order_number: outOrderNumber, pay_url: payUrl, order_number: data.data && data.data.order_number ? data.data.order_number : null });
                }
            );
        } catch (e) {
            return res.status(502).json({ error: 'NicePay create order error' });
        }
    });
});

app.get('/api/nicepay/notify', (req, res) => {
    res.status(405).send('Method Not Allowed');
});

app.post('/api/nicepay/notify', (req, res) => {
    const payload = { ...(req.body || {}) };
    const key = (process.env.NICEPAY_KEY || '').trim();
    if (!key) return res.status(500).send('fail');

    const expectedIp = (process.env.NICEPAY_CALLBACK_IP || '').trim();
    const clientIp = getRequestIp(req);
    if (process.env.NODE_ENV === 'production' && expectedIp) {
        const allow = expectedIp.split(',').map(s => s.trim()).filter(Boolean);
        if (allow.length && clientIp && !allow.includes(clientIp)) return res.status(403).send('fail');
    }

    const merchantId = (process.env.NICEPAY_MERCHANT_ID || '').trim();
    if (merchantId && payload.merchant_id && String(payload.merchant_id).trim() !== merchantId) return res.status(400).send('fail');

    const receivedSign = payload.sign;
    const computedA = nicePaySign(payload, key);
    const computedB = nicePaySign({ ...payload, action: 'callback' }, key);
    const receivedUp = receivedSign ? String(receivedSign).trim().toUpperCase() : '';
    if (!receivedUp || (receivedUp !== computedA && receivedUp !== computedB)) return res.status(400).send('fail');

    const outOrderNumber = (payload.out_order_number || payload.outOrderNumber || payload.order_no || payload.orderNo || '').toString().trim();
    if (!outOrderNumber) return res.status(400).send('fail');

    db.get("SELECT * FROM payment_orders WHERE provider = 'nicepay' AND out_order_number = ?", [outOrderNumber], (err, order) => {
        if (err || !order) return res.send('success');
        if (order.status === 'paid') return res.send('success');

        const realAmount = payload.real_amount !== undefined && payload.real_amount !== null ? Number(payload.real_amount) : null;
        if (realAmount !== null && Number.isFinite(realAmount) && !nicePayAmountMatches(realAmount, order.amount)) {
            db.run("UPDATE payment_orders SET status = ? WHERE id = ?", ['failed', order.id], () => res.send('success'));
            return;
        }

        const paid = isNicePayPaid(payload);
        if (!paid) {
            db.run("UPDATE payment_orders SET status = ? WHERE id = ?", ['failed', order.id], () => res.send('success'));
            return;
        }

        db.serialize(() => {
            db.run("UPDATE payment_orders SET status = 'paid', paid_at = ? WHERE id = ?", [new Date().toISOString(), order.id], () => {
                const depositGateway = order.order_type === 'subscription' ? 'NicePay Subscription' : (order.order_type === 'double_profit' ? 'NicePay Double Profit' : 'NicePay');
                const depositTrx = outOrderNumber;
                db.get("SELECT * FROM deposits WHERE transaction_id = ?", [depositTrx], (e2, existing) => {
                    if (existing && existing.status === 'approved') return res.send('success');

                    db.run(
                        "INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [order.user_id, order.amount, depositGateway, depositTrx, 'approved', new Date().toISOString(), null],
                        function () {
                            if (order.order_type === 'subscription') {
                                db.get("SELECT duration, daily_limit FROM plans WHERE id = ?", [order.plan_id], (e3, plan) => {
                                    if (!plan) return res.send('success');
                                    const expiry = new Date(Date.now() + Number(plan.duration) * 24 * 60 * 60 * 1000).toISOString();
                                    const startedAt = new Date().toISOString();
                                    const totalAds = Number(plan.daily_limit) || 0;
                                    db.run("UPDATE users SET plan_id = ?, plan_expiry = ?, plan_started_at = ?, plan_ads_used = 0, plan_ads_total = ?, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ?", [order.plan_id, expiry, startedAt, totalAds, order.user_id], () => res.send('success'));
                                });
                            } else if (order.order_type === 'double_profit') {
                                const paidAt = new Date().toISOString();
                                db.run(
                                    "UPDATE double_profit_offer_purchases SET payment_status = 'paid', paid_at = ? WHERE user_id = ? AND plan_id = ? AND out_order_number = ?",
                                    [paidAt, order.user_id, order.plan_id, outOrderNumber],
                                    () => res.send('success')
                                );
                            } else {
                                db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [order.amount, order.user_id], () => {
                                    awardReferralDepositCommission({ referredUserId: order.user_id, depositAmount: order.amount, sourceTransactionId: depositTrx });
                                    res.send('success');
                                });
                            }
                        }
                    );
                });
            });
        });
    });
});

app.get('/api/nicepay/order/:outOrder', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const outOrder = String(req.params.outOrder || '').trim();
    if (!outOrder) return res.status(400).json({ error: 'Invalid order' });

    db.get("SELECT * FROM payment_orders WHERE provider = 'nicepay' AND out_order_number = ? AND user_id = ?", [outOrder, req.session.user.id], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!row) return res.status(404).json({ error: 'Not found' });
        res.json(row);
    });
});

app.get('/api/settings/subscription-help', (req, res) => {
    db.get("SELECT value FROM settings WHERE key = 'subscription_help_media' LIMIT 1", (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ media_url: row && row.value ? String(row.value) : '' });
    });
});

function resolveHelpMediaKey(page) {
    const p = String(page || '').trim().toLowerCase();
    if (!p || !/^[a-z0-9_-]+$/.test(p)) return null;
    if (p === 'subscriptions' || p === 'subscription') return 'subscription_help_media';
    return `help_media_${p}`;
}

app.get('/api/settings/help-media', (req, res) => {
    const key = resolveHelpMediaKey(req.query.page);
    if (!key) return res.status(400).json({ error: 'Invalid page' });
    db.get("SELECT value FROM settings WHERE key = ? LIMIT 1", [key], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ media_url: row && row.value ? String(row.value) : '' });
    });
});

app.post('/api/admin/settings/help-media', upload.single('media'), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const key = resolveHelpMediaKey(req.body && req.body.page);
    if (!key) return res.status(400).json({ error: 'Invalid page' });

    const clear = req.body && (req.body.clear === '1' || req.body.clear === 'true');
    if (clear) {
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, '')", [key], (err) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, media_url: '' });
        });
        return;
    }

    if (!req.file || !req.file.filename) {
        return res.status(400).json({ error: 'No media uploaded' });
    }

    const mediaUrl = `/uploads/${req.file.filename}`;
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", [key, mediaUrl], (err) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, media_url: mediaUrl });
    });
});

app.post('/api/admin/settings/subscription-help', upload.single('media'), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const clear = req.body && (req.body.clear === '1' || req.body.clear === 'true');
    if (clear) {
        db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('subscription_help_media', '')", (err) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, media_url: '' });
        });
        return;
    }

    if (!req.file || !req.file.filename) {
        return res.status(400).json({ error: 'No media uploaded' });
    }

    const mediaUrl = `/uploads/${req.file.filename}`;
    db.run("INSERT OR REPLACE INTO settings (key, value) VALUES ('subscription_help_media', ?)", [mediaUrl], (err) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, media_url: mediaUrl });
    });
});

// Admin API: Save General Settings
app.post('/api/admin/settings/general', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { referral_signup_bonus, joining_bonus, site_name, currency_symbol, min_withdraw_amount, referral_deposit_commission_pct, community_enabled, community_group_url, community_fake_chat_enabled, community_fake_user_count, community_message_interval_ms } = req.body;
    
    db.serialize(() => {
        const stmt = db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
        
        if (referral_signup_bonus !== undefined) stmt.run('referral_signup_bonus', referral_signup_bonus);
        if (joining_bonus !== undefined) stmt.run('joining_bonus', joining_bonus);
        if (site_name !== undefined) stmt.run('site_name', site_name);
        if (currency_symbol !== undefined) stmt.run('currency_symbol', currency_symbol);
        if (min_withdraw_amount !== undefined) stmt.run('min_withdraw_amount', min_withdraw_amount);
        if (referral_deposit_commission_pct !== undefined) stmt.run('referral_deposit_commission_pct', referral_deposit_commission_pct);
        if (community_enabled !== undefined) stmt.run('community_enabled', community_enabled);
        if (community_group_url !== undefined) stmt.run('community_group_url', community_group_url);
        if (community_fake_chat_enabled !== undefined) stmt.run('community_fake_chat_enabled', community_fake_chat_enabled);
        if (community_fake_user_count !== undefined) stmt.run('community_fake_user_count', community_fake_user_count);
        if (community_message_interval_ms !== undefined) stmt.run('community_message_interval_ms', community_message_interval_ms);
        
        stmt.finalize();
        res.json({ success: true });
    });
});

// Admin API: Get Dashboard Stats
app.get('/api/admin/stats', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }

    const stats = {};

    db.serialize(() => {
        // 1. Total Users
        db.get("SELECT COUNT(*) as count FROM users WHERE role = 'user'", (err, row) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            stats.totalUsers = row.count;

            // 2. Total Deposits (Approved)
            db.get("SELECT COALESCE(SUM(d.amount), 0) as total FROM deposits d JOIN users u ON u.id = d.user_id WHERE d.status = 'approved'", (err, row) => {
                if (err) return res.status(500).json({ error: 'DB Error' });
                stats.totalDeposits = row.total || 0;

                // 3. Pending Withdrawals
                db.get("SELECT COUNT(*) as count FROM withdrawals w JOIN users u ON u.id = w.user_id WHERE w.status = 'pending'", (err, row) => {
                    if (err) return res.status(500).json({ error: 'DB Error' });
                    stats.pendingWithdrawals = row.count;

                    // 4. Total Withdrawn (Approved)
                    db.get("SELECT COALESCE(SUM(w.amount), 0) as total FROM withdrawals w JOIN users u ON u.id = w.user_id WHERE w.status = 'approved'", (err, row) => {
                        if (err) return res.status(500).json({ error: 'DB Error' });
                        stats.totalWithdrawn = row.total || 0;

                    // 4. Pending KYC (Disabled)
                    // db.get("SELECT COUNT(*) as count FROM kyc_requests WHERE status = 'pending'", (err, row) => {
                        // if (err) return res.status(500).json({ error: 'DB Error' });
                        // stats.pendingKYC = row.count;
                        stats.pendingKYC = 0; // Disabled

                        // 5. Recent Users
                        db.all("SELECT username, email, country, created_at FROM users WHERE role = 'user' ORDER BY id DESC LIMIT 5", (err, rows) => {
                            if (err) return res.status(500).json({ error: 'DB Error' });
                            stats.recentUsers = rows;
                            res.json(stats);
                        });
                    // });
                    });
                });
            });
        });
    });
});

// User API: Subscribe to Plan (Request)
app.post('/api/user/subscribe', (req, res, next) => {
    const disabled = String(process.env.MANUAL_SUBSCRIPTION_DISABLED || '').trim().toLowerCase();
    if (disabled === '1' || disabled === 'true' || disabled === 'yes') {
        if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
        return res.status(410).json({ error: 'Manual subscription is disabled. Please use NicePay payment.' });
    }
    return next();
});

// User API: Get Ads
app.get('/api/user/ads', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const userId = req.session.user.id;
    
    // 1. Check User's Plan
    db.get("SELECT plan_id, plan_expiry, plan_started_at, plan_ads_total FROM users WHERE id = ?", [userId], (err, user) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        
        // If no plan or plan expired
        if (!user.plan_id || new Date(user.plan_expiry) < new Date()) {
            return res.json([]); // No ads for users without active plan
        }
        
        // 2. Get Plan Limit
        db.get("SELECT daily_limit, duration FROM plans WHERE id = ?", [user.plan_id], (err, plan) => {
            if (err || !plan) return res.json([]); // Should not happen if plan_id is valid
            
            const totalAllowed = Number(user.plan_ads_total) > 0 ? Number(user.plan_ads_total) : (Number(plan.daily_limit) || 0);
            if (totalAllowed <= 0) return res.json([]);

            const expiry = new Date(user.plan_expiry);
            const isValidExpiry = !isNaN(expiry.getTime());
            const durationDays = Number(plan.duration) || 0;

            const parseIso = (v) => {
                const d = v ? new Date(v) : null;
                return d && !isNaN(d.getTime()) ? d.toISOString() : null;
            };

            const fromUser = parseIso(user.plan_started_at);

            const inferFromExpiry = () => {
                if (!isValidExpiry || durationDays <= 0) return null;
                const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                return start.toISOString();
            };

            const loadPlanStart = (cb) => {
                if (fromUser) return cb(fromUser);
                db.get(
                    "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                    [userId],
                    (sErr, sRow) => {
                        if (!sErr && sRow && sRow.created_at) {
                            const iso = parseIso(sRow.created_at);
                            if (iso) return cb(iso);
                        }
                        cb(inferFromExpiry());
                    }
                );
            };

            loadPlanStart((startIso) => {
                const start = startIso || '1970-01-01T00:00:00.000Z';
                db.get(
                    "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                    [userId, start],
                    (cErr, cRow) => {
                        if (cErr) return res.status(500).json({ error: 'DB Error' });
                        const used = cRow && cRow.count ? Number(cRow.count) : 0;
                        const remaining = totalAllowed - used;
                        if (remaining <= 0) {
                            return res.status(403).json({ error: 'Your plan is finished. Subscribe your next plan.' });
                        }

                        const planId = user.plan_id;
                        const fetchLimit = Math.max(1, Math.min(Math.max(totalAllowed, remaining), 200));

                        db.all(
                            "SELECT * FROM ads WHERE status = 'active' AND (plan_id = ? OR plan_id IS NULL OR plan_id = 0) ORDER BY RANDOM() LIMIT ?",
                            [planId, fetchLimit],
                            (aErr, ads) => {
                                if (aErr) return res.status(500).json({ error: 'DB Error' });

                                db.all(
                                    "SELECT transaction_id FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                                    [userId, start],
                                    (vErr, views) => {
                                        if (vErr) return res.status(500).json({ error: 'DB Error fetching views' });

                                        const viewedAdIds = (views || []).map(v => {
                                            const parts = String(v.transaction_id || '').split('-');
                                            return parts.length >= 2 ? parseInt(parts[1]) : null;
                                        }).filter(v => Number.isFinite(v));

                                        const adsWithStatus = (ads || []).map(ad => ({
                                            ...ad,
                                            completed: viewedAdIds.includes(ad.id)
                                        }));

                                        const displayCount = Math.max(1, Number(totalAllowed) || 0);
                                        const sorted = adsWithStatus.slice().sort((a, b) => {
                                            if (!!a.completed === !!b.completed) return 0;
                                            return a.completed ? 1 : -1;
                                        });
                                        res.json(sorted.slice(0, displayCount));
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    });
});

app.get('/api/user/double-profit/offer', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const userId = req.session.user.id;
    const adId = req.query && req.query.ad_id !== undefined && req.query.ad_id !== null ? Number(req.query.ad_id) : null;
    const safeAdId = Number.isFinite(adId) && adId > 0 ? adId : null;

    db.get("SELECT plan_id, plan_expiry, plan_started_at, plan_ads_total, double_profit_unlocked, double_profit_disabled FROM users WHERE id = ?", [userId], (uErr, user) => {
        if (uErr) return res.status(500).json({ error: 'DB Error' });
        if (!user || !user.plan_id || new Date(user.plan_expiry) < new Date()) {
            return res.json({ show: false });
        }
        if (Number(user.double_profit_disabled) === 1) return res.json({ show: false });

        db.get("SELECT duration, daily_limit, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
            if (pErr || !plan) return res.json({ show: false });

            if (Number(user.double_profit_unlocked) === 1) return res.json({ show: false });

            const totalAllowed = Number(user.plan_ads_total) > 0 ? Number(user.plan_ads_total) : (Number(plan.daily_limit) || 0);
            if (totalAllowed <= 0) return res.json({ show: false });

            const expiry = new Date(user.plan_expiry);
            const isValidExpiry = !isNaN(expiry.getTime());
            const durationDays = Number(plan.duration) || 0;

            const parseIso = (v) => {
                const d = v ? new Date(v) : null;
                return d && !isNaN(d.getTime()) ? d.toISOString() : null;
            };

            const fromUser = parseIso(user.plan_started_at);

            const inferFromExpiry = () => {
                if (!isValidExpiry || durationDays <= 0) return null;
                const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                return start.toISOString();
            };

            const loadPlanStart = (cb) => {
                if (fromUser) return cb(fromUser);
                db.get(
                    "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                    [userId],
                    (sErr, sRow) => {
                        if (!sErr && sRow && sRow.created_at) {
                            const iso = parseIso(sRow.created_at);
                            if (iso) return cb(iso);
                        }
                        cb(inferFromExpiry());
                    }
                );
            };

            loadPlanStart((startIso) => {
                const start = startIso || '1970-01-01T00:00:00.000Z';
                db.get(
                    "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                    [userId, start],
                    (cErr, cRow) => {
                        if (cErr) return res.status(500).json({ error: 'DB Error' });
                        const used = cRow && cRow.count ? Number(cRow.count) : 0;

                        db.get(
                            "SELECT id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE plan_id = ? AND status = 'active' AND after_ads = ? ORDER BY id ASC LIMIT 1",
                            [user.plan_id, used],
                            (oErr, offer) => {
                                if (oErr) return res.json({ show: false });

                                const offerId = offer && offer.id ? Number(offer.id) : null;
                                const afterAds = offer ? Number(offer.after_ads) || 0 : (Number(plan.double_profit_after_ads) || 0);
                                const fee = offer ? Number(offer.fee) || 0 : (Number(plan.double_profit_fee) || 0);
                                const bonusPct = offer ? Number(offer.bonus_pct) || 0 : (Number(plan.double_profit_bonus_pct) || 0);
                                if (afterAds <= 0 || fee <= 0 || bonusPct <= 0) return res.json({ show: false });
                                if (used !== afterAds) return res.json({ show: false });

                                db.get(
                                    "SELECT id, payment_status, fee FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND offer_after_ads = ? AND used_at IS NULL AND created_at >= ? ORDER BY id DESC LIMIT 1",
                                    [userId, user.plan_id, afterAds, start],
                                    (p2Err, existing) => {
                                        if (p2Err) return res.json({ show: false });
                                        if (existing) {
                                            const st = existing.payment_status ? String(existing.payment_status).toLowerCase() : 'paid';
                                            if (st === 'paid' || Number(existing.fee) === 0) return res.json({ show: false });
                                        }
                                        return res.json({ show: true, offer_id: offerId, fee, bonus_pct: bonusPct, after_ads: afterAds, ad_id: safeAdId });
                                    }
                                );
                            }
                        );
                    }
                );
            });
        });
    });
});

app.post('/api/user/double-profit/purchase', bodyParser.json(), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const userId = req.session.user.id;
    const adId = req.body && req.body.ad_id !== undefined && req.body.ad_id !== null ? Number(req.body.ad_id) : null;
    const offerIdRaw = req.body && req.body.offer_id !== undefined && req.body.offer_id !== null ? Number(req.body.offer_id) : null;
    if (!Number.isFinite(adId) || adId <= 0) return res.status(400).json({ error: 'Invalid ad_id' });

    const merchantId = (process.env.NICEPAY_MERCHANT_ID || '').trim();
    const gateId = (process.env.NICEPAY_GATE_ID || '').trim();
    const key = (process.env.NICEPAY_KEY || '').trim();
    const orderApiUrl = (process.env.NICEPAY_ORDER_API_URL || '').trim();
    const appBaseUrl = (process.env.APP_BASE_URL || '').trim();
    const notifyUrl = (process.env.NICEPAY_NOTIFY_URL || (appBaseUrl ? `${appBaseUrl.replace(/\/+$/, '')}/api/nicepay/notify` : '')).trim();

    if (!merchantId || !gateId || !key || !orderApiUrl) {
        return res.status(500).json({ error: 'NicePay not configured' });
    }
    if (!notifyUrl) return res.status(500).json({ error: 'NicePay notify_url not configured' });

    db.get("SELECT id, plan_id, plan_expiry, plan_started_at, plan_ads_total, double_profit_disabled FROM users WHERE id = ?", [userId], (uErr, user) => {
        if (uErr) return res.status(500).json({ error: 'DB Error' });
        if (!user || !user.plan_id || new Date(user.plan_expiry) < new Date()) {
            return res.status(400).json({ error: 'No active plan' });
        }
        if (Number(user.double_profit_disabled) === 1) {
            return res.status(400).json({ error: 'Double profit disabled for this user' });
        }

        db.get("SELECT id, duration, daily_limit, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
            if (pErr || !plan) return res.status(400).json({ error: 'Plan error' });

            const totalAllowed = Number(user.plan_ads_total) > 0 ? Number(user.plan_ads_total) : (Number(plan.daily_limit) || 0);
            if (totalAllowed <= 0) return res.status(400).json({ error: 'Plan error' });

            const expiry = new Date(user.plan_expiry);
            const isValidExpiry = !isNaN(expiry.getTime());
            const durationDays = Number(plan.duration) || 0;

            const parseIso = (v) => {
                const d = v ? new Date(v) : null;
                return d && !isNaN(d.getTime()) ? d.toISOString() : null;
            };

            const fromUser = parseIso(user.plan_started_at);

            const inferFromExpiry = () => {
                if (!isValidExpiry || durationDays <= 0) return null;
                const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                return start.toISOString();
            };

            const loadPlanStart = (cb) => {
                if (fromUser) return cb(fromUser);
                db.get(
                    "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                    [userId],
                    (sErr, sRow) => {
                        if (!sErr && sRow && sRow.created_at) {
                            const iso = parseIso(sRow.created_at);
                            if (iso) return cb(iso);
                        }
                        cb(inferFromExpiry());
                    }
                );
            };

            loadPlanStart((startIso) => {
                const start = startIso || '1970-01-01T00:00:00.000Z';
                db.get(
                    "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                    [userId, start],
                    (cErr, cRow) => {
                        if (cErr) return res.status(500).json({ error: 'DB Error' });
                        const used = cRow && cRow.count ? Number(cRow.count) : 0;

                        const pickOffer = (cb) => {
                            if (Number.isFinite(offerIdRaw) && offerIdRaw > 0) {
                                db.get(
                                    "SELECT id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE id = ? AND plan_id = ? AND status = 'active' LIMIT 1",
                                    [offerIdRaw, user.plan_id],
                                    (oErr, offer) => cb(oErr, offer)
                                );
                                return;
                            }
                            db.get(
                                "SELECT id, after_ads, fee, bonus_pct FROM double_profit_offers WHERE plan_id = ? AND status = 'active' AND after_ads = ? ORDER BY id ASC LIMIT 1",
                                [user.plan_id, used],
                                (oErr, offer) => cb(oErr, offer)
                            );
                        };

                        pickOffer((oErr, offer) => {
                            if (oErr) return res.status(500).json({ error: 'DB Error' });

                            const offerId = offer && offer.id ? Number(offer.id) : null;
                            const afterAds = offer ? Number(offer.after_ads) || 0 : (Number(plan.double_profit_after_ads) || 0);
                            const fee = offer ? Number(offer.fee) || 0 : (Number(plan.double_profit_fee) || 0);
                            const bonusPct = offer ? Number(offer.bonus_pct) || 0 : (Number(plan.double_profit_bonus_pct) || 0);
                            if (afterAds <= 0 || fee <= 0 || bonusPct <= 0) return res.status(400).json({ error: 'Double profit not available' });
                            if (used !== afterAds) return res.status(400).json({ error: 'Not eligible yet' });

                            db.get(
                                "SELECT id, payment_status FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND offer_after_ads = ? AND used_at IS NULL AND created_at >= ? ORDER BY id DESC LIMIT 1",
                                [userId, user.plan_id, afterAds, start],
                                (xErr, existing) => {
                                    if (xErr) return res.status(500).json({ error: 'DB Error' });
                                    if (existing) {
                                        const st = existing.payment_status ? String(existing.payment_status).toLowerCase() : 'paid';
                                        if (st === 'paid') return res.json({ success: true });
                                    }

                                    const outOrderNumber = `DP-${user.plan_id}-${afterAds}-${Date.now()}-${userId}`;
                                    const amount = String(fee);
                                    const params = {
                                        out_order_number: outOrderNumber,
                                        amount,
                                        merchant_id: merchantId,
                                        gate_id: gateId,
                                        notify_url: notifyUrl
                                    };
                                    const sign = nicePaySign(params, key);
                                    const payload = { ...params, sign };

                                    (async () => {
                                        try {
                                            const apiRes = await fetch(orderApiUrl, {
                                                method: 'POST',
                                                headers: { 'Content-Type': 'application/json' },
                                                body: JSON.stringify(payload)
                                            });
                                            const data = await apiRes.json().catch(() => ({}));
                                            if (!apiRes.ok) return res.status(502).json({ error: 'NicePay create order failed', details: data });
                                            if (!data || data.code !== 0) return res.status(502).json({ error: data && data.msg ? String(data.msg) : 'NicePay create order failed', details: data });
                                            const payUrl = data && data.data && data.data.pay_url ? String(data.data.pay_url) : '';
                                            if (!payUrl) return res.status(502).json({ error: 'NicePay pay_url missing', details: data });

                                            const nowIso = new Date().toISOString();
                                            db.serialize(() => {
                                                db.run(
                                                    "INSERT OR IGNORE INTO payment_orders (provider, out_order_number, user_id, order_type, plan_id, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                                    ['nicepay', outOrderNumber, userId, 'double_profit', user.plan_id, fee, 'pending', nowIso]
                                                );
                                                
                                                if (existing) {
                                                    db.run(
                                                        "UPDATE double_profit_offer_purchases SET out_order_number = ?, ad_id = ? WHERE id = ?",
                                                        [outOrderNumber, adId, existing.id],
                                                        (uErr) => {
                                                            if (uErr) return res.status(500).json({ error: 'DB Error' });
                                                            res.json({ success: true, pay_url: payUrl, out_order_number: outOrderNumber });
                                                        }
                                                    );
                                                } else {
                                                    db.run(
                                                        "INSERT INTO double_profit_offer_purchases (user_id, plan_id, ad_id, offer_id, offer_after_ads, fee, bonus_pct, out_order_number, payment_status, paid_at, used_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?)",
                                                        [userId, user.plan_id, adId, offerId, afterAds, fee, bonusPct, outOrderNumber, 'pending', nowIso],
                                                        (iErr) => {
                                                            if (iErr) return res.status(500).json({ error: 'DB Error' });
                                                            res.json({ success: true, pay_url: payUrl, out_order_number: outOrderNumber });
                                                        }
                                                    );
                                                }
                                            });
                                        } catch {
                                            return res.status(502).json({ error: 'NicePay create order error' });
                                        }
                                    })();
                                }
                            );
                        });
                    }
                );
            });
        });
    });
});

// User API: Get My Ads (Completed & Pending Tasks)
app.get('/api/user/my-ads', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const userId = req.session.user.id;
    
    db.get("SELECT double_profit_disabled FROM users WHERE id = ?", [userId], (uErr, uRow) => {
        const dpDisabled = !uErr && uRow && Number(uRow.double_profit_disabled) === 1;

        // Join deposits (transactions) with ads to get details of viewed ads
        db.all(`
            SELECT ads.*, deposits.created_at as viewed_at, deposits.amount as earned_amount 
            FROM deposits 
            JOIN ads ON deposits.transaction_id LIKE 'AD-' || ads.id || '-%' 
            WHERE deposits.user_id = ? AND deposits.gateway = 'Ad View'
            ORDER BY deposits.id DESC
        `, [userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB Error' });

            if (dpDisabled) return res.json(rows);
            
            // Also fetch pending double profit tasks
            db.all(`
                SELECT id, fee, bonus_pct, created_at, payment_status, offer_after_ads
                FROM double_profit_offer_purchases 
                WHERE user_id = ? AND used_at IS NULL AND (payment_status = 'pending' OR payment_status = 'paid')
                ORDER BY id DESC
            `, [userId], (dpErr, dpRows) => {
                if (dpErr) return res.json(rows);
                
                const pendingTasks = dpRows.map(dp => ({
                    id: 'dp-' + dp.id,
                    title: 'Double Profit Task (' + (dp.payment_status === 'paid' ? 'Paid - Watch Ad' : 'Pending Payment') + ')',
                    url: '',
                    earned_amount: 'Fee: ' + dp.fee + ' PKR | Bonus: ' + dp.bonus_pct + '%',
                    viewed_at: dp.created_at,
                    is_pending_task: true,
                    payment_status: dp.payment_status
                }));
                
                res.json([...pendingTasks, ...rows]);
            });
        });
    });
});

// User API: Get My Earnings
app.get('/api/user/earnings', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const userId = req.session.user.id;
    
    db.all(`
        SELECT * FROM deposits 
        WHERE user_id = ? AND gateway = 'Ad View' 
        ORDER BY id DESC
    `, [userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// User API: View Ad (Claim Reward)
app.post('/api/user/ads/view', bodyParser.json(), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { ad_id } = req.body;
    
    db.get("SELECT * FROM ads WHERE id = ? AND status = 'active'", [ad_id], (err, ad) => {
        if (err || !ad) return res.status(404).json({ error: 'Ad not found or inactive' });
        const userId = req.session.user.id;
        db.get("SELECT plan_id, plan_expiry, plan_started_at, plan_ads_total, double_profit_unlocked, double_profit_bonus_pct, double_profit_disabled FROM users WHERE id = ?", [userId], (uErr, user) => {
            if (uErr || !user || !user.plan_id || new Date(user.plan_expiry) < new Date()) {
                return res.status(400).json({ error: 'No active plan' });
            }

            db.get("SELECT daily_limit, duration FROM plans WHERE id = ?", [user.plan_id], (pErr, plan) => {
                if (pErr || !plan) return res.status(400).json({ error: 'Plan error' });

                const totalAllowed = Number(user.plan_ads_total) > 0 ? Number(user.plan_ads_total) : (Number(plan.daily_limit) || 0);
                if (totalAllowed <= 0) return res.status(400).json({ error: 'Plan error' });

                const expiry = new Date(user.plan_expiry);
                const isValidExpiry = !isNaN(expiry.getTime());
                const durationDays = Number(plan.duration) || 0;

                const parseIso = (v) => {
                    const d = v ? new Date(v) : null;
                    return d && !isNaN(d.getTime()) ? d.toISOString() : null;
                };

                const fromUser = parseIso(user.plan_started_at);

                const inferFromExpiry = () => {
                    if (!isValidExpiry || durationDays <= 0) return null;
                    const start = new Date(expiry.getTime() - durationDays * 24 * 60 * 60 * 1000);
                    return start.toISOString();
                };

                const loadPlanStart = (cb) => {
                    if (fromUser) return cb(fromUser);
                    db.get(
                        "SELECT created_at FROM deposits WHERE user_id = ? AND (gateway IN ('NicePay Subscription','Wallet Subscription') OR transaction_id LIKE 'SUB-%') AND status IN ('approved','completed') ORDER BY id DESC LIMIT 1",
                        [userId],
                        (sErr, sRow) => {
                            if (!sErr && sRow && sRow.created_at) {
                                const iso = parseIso(sRow.created_at);
                                if (iso) return cb(iso);
                            }
                            cb(inferFromExpiry());
                        }
                    );
                };

                loadPlanStart((startIso) => {
                    const start = startIso || inferFromExpiry() || new Date().toISOString();

                    db.get(
                        "SELECT id FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND transaction_id LIKE ? AND created_at >= ?",
                        [userId, `AD-${ad_id}-%`, start],
                        (eErr, existing) => {
                            if (eErr) return res.status(500).json({ error: 'DB Error' });
                            if (existing) return res.status(400).json({ error: 'Ad already viewed' });

                            db.get(
                                "SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View' AND created_at >= ?",
                                [userId, start],
                                (cErr, row) => {
                                    if (cErr) return res.status(500).json({ error: 'DB Error' });
                                    const used = row && row.count ? Number(row.count) : 0;
                                    if (used >= totalAllowed) {
                                        return res.status(400).json({ error: 'Your plan is finished. Subscribe your next plan.' });
                                    }

                                    const applyReward = (dpRow) => {
                                        const disabled = Number(user.double_profit_disabled) === 1;
                                        const unlocked = !disabled && Number(user.double_profit_unlocked) === 1;
                                        const userBonusPct = !disabled ? (Number(user.double_profit_bonus_pct) || 0) : 0;
                                        const offerBonusPct = !disabled && dpRow && dpRow.bonus_pct !== undefined && dpRow.bonus_pct !== null ? Number(dpRow.bonus_pct) || 0 : 0;
                                        const bonusPct = offerBonusPct > 0 ? offerBonusPct : (unlocked ? userBonusPct : 0);

                                        let rewardToAdd = Number(ad.reward) || 0;
                                        if (bonusPct > 0) {
                                            rewardToAdd = rewardToAdd * (1 + (bonusPct / 100));
                                        }
                                        rewardToAdd = Math.round(rewardToAdd * 100) / 100;

                                        db.run(
                                            "UPDATE users SET balance = balance + ?, plan_ads_used = COALESCE(plan_ads_used, 0) + 1, plan_ads_total = ?, plan_started_at = COALESCE(plan_started_at, ?) WHERE id = ?",
                                            [rewardToAdd, totalAllowed, startIso || start, userId],
                                            (bErr) => {
                                                if (bErr) return res.status(500).json({ error: 'DB Error updating balance' });

                                                const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
                                                stmt.run(userId, rewardToAdd, 'Ad View', `AD-${ad_id}-${Date.now()}`, 'completed', new Date().toISOString(), function (iErr) {
                                                    if (iErr) console.error("Error logging ad view transaction:", iErr);
                                                    if (!disabled && dpRow && dpRow.id) {
                                                        const usedAt = new Date().toISOString();
                                                        if (dpRow.ad_id === null || dpRow.ad_id === undefined) {
                                                            db.run("UPDATE double_profit_offer_purchases SET ad_id = ?, used_at = ? WHERE id = ? AND used_at IS NULL", [Number(ad_id), usedAt, dpRow.id], () => {
                                                                res.json({ success: true, reward: rewardToAdd });
                                                            });
                                                            return;
                                                        }
                                                        db.run("UPDATE double_profit_offer_purchases SET used_at = ? WHERE id = ? AND used_at IS NULL", [usedAt, dpRow.id], () => {
                                                            res.json({ success: true, reward: rewardToAdd });
                                                        });
                                                        return;
                                                    }
                                                    res.json({ success: true, reward: rewardToAdd });
                                                });
                                                stmt.finalize();
                                            }
                                        );
                                    };

                                    if (Number(user.double_profit_disabled) === 1) return applyReward(null);

                                    db.get(
                                        "SELECT id, ad_id, bonus_pct FROM double_profit_offer_purchases WHERE user_id = ? AND plan_id = ? AND offer_after_ads = ? AND used_at IS NULL AND created_at >= ? AND (payment_status = 'paid' OR fee = 0) AND (ad_id = ? OR ad_id IS NULL) ORDER BY CASE WHEN ad_id IS NULL THEN 1 ELSE 0 END, id DESC LIMIT 1",
                                        [userId, user.plan_id, used, start, Number(ad_id)],
                                        (dpErr, dpRow) => {
                                            if (dpErr) return res.status(500).json({ error: 'DB Error' });
                                            applyReward(dpRow);
                                        }
                                    );
                                }
                            );
                        }
                    );
                });
            });
        });
    });
});

// User API: Withdraw Request
app.post('/api/user/withdraw', bodyParser.json(), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    const { amount, method, account_details } = req.body;
    const userId = req.session.user.id;
    const amountVal = parseFloat(amount);
    
    if (isNaN(amountVal) || amountVal <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }
    
    if (!method || !account_details) {
        return res.status(400).json({ error: 'Please provide payment method and account details' });
    }

    // Check balance (but don't deduct yet)
    db.get("SELECT users.balance, users.plan_id, users.withdrawal_error_active, users.withdrawal_error_text FROM users WHERE users.id = ?", [userId], (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!row) return res.status(404).json({ error: 'User not found' });
        
        // Check Withdrawal Error Status
        if (row.withdrawal_error_active) {
            return res.status(400).json({ error: row.withdrawal_error_text || 'Withdrawal is currently unavailable for your account.' });
        }

        db.get("SELECT value FROM settings WHERE key = 'min_withdraw_amount' LIMIT 1", (sErr, sRow) => {
            const globalMin = !sErr && sRow && sRow.value !== undefined && sRow.value !== null ? Number(sRow.value) || 0 : 0;
            const requiredMin = Math.max(0, Number(globalMin) || 0);

            if (amountVal < requiredMin) {
                return res.status(400).json({ error: `Minimum withdrawal amount is ${requiredMin}` });
            }

            if (row.balance < amountVal) {
                return res.status(400).json({ error: 'Insufficient balance' });
            }

            const stmt = db.prepare("INSERT INTO withdrawals (user_id, amount, method, account_details, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
            stmt.run(userId, amountVal, method, account_details, 'pending', new Date().toISOString(), function(err) {
                if (err) {
                    console.error("Error logging withdrawal:", err);
                    return res.status(500).json({ error: 'DB Error creating withdrawal request' });
                }
                res.json({ success: true });
            });
            stmt.finalize();
        });
    });
});

// User API: Internal Fund Transfer
app.post('/api/user/transfer', bodyParser.json(), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const { email, amount } = req.body;
    const senderId = req.session.user.id;
    const amountVal = parseFloat(amount);

    if (!email || !amount) return res.status(400).json({ error: 'Please fill in all fields' });
    if (isNaN(amountVal) || amountVal <= 0) return res.status(400).json({ error: 'Invalid amount' });

    if (email === req.session.user.email) return res.status(400).json({ error: 'Cannot transfer to yourself' });

    db.serialize(() => {
        // 1. Check Recipient
        db.get("SELECT id, email FROM users WHERE email = ?", [email], (err, recipient) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            if (!recipient) return res.status(404).json({ error: 'This user not exist' });

            // 2. Check Sender Balance
            db.get("SELECT balance FROM users WHERE id = ?", [senderId], (err, sender) => {
                if (err) return res.status(500).json({ error: 'DB Error' });
                if (sender.balance < amountVal) return res.status(400).json({ error: 'Insufficient balance' });

                // 3. Perform Transfer
                // Deduct from sender
                db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [amountVal, senderId], (err) => {
                    if (err) return res.status(500).json({ error: 'DB Error deducting funds' });

                    // Add to recipient
                    db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [amountVal, recipient.id], (err) => {
                        if (err) {
                            // Rollback deduction
                            db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [amountVal, senderId]);
                            return res.status(500).json({ error: 'DB Error adding funds' });
                        }
                        
                        // Log transaction
                        db.run("INSERT INTO transfers (sender_id, receiver_id, amount, created_at) VALUES (?, ?, ?, ?)", [senderId, recipient.id, amountVal, new Date().toISOString()], (err) => {
                            if (err) console.error("Error logging transfer:", err);
                            res.json({ success: true });
                        });
                    });
                });
            });
        });
    });
});

// Admin API: Create Ad
app.post('/api/admin/ads', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { title, url, duration, reward, plan_id } = req.body;
    
    // Extract YouTube ID to clean up the URL
    // This handles standard links, short links, and embed links
    let cleanUrl = url;
    if (url && (url.includes('youtube.com') || url.includes('youtu.be'))) {
        const regExp = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]*).*/;
        const match = url.match(regExp);
        if (match && match[2].length === 11) {
            cleanUrl = `https://www.youtube.com/watch?v=${match[2]}`;
        }
    }

    const stmt = db.prepare("INSERT INTO ads (title, url, duration, reward, status, created_at, plan_id) VALUES (?, ?, ?, ?, 'active', ?, ?)");
    stmt.run(title, cleanUrl, duration, reward, new Date().toISOString(), plan_id || null, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

// Admin API: Update Ad
app.put('/api/admin/ads/:id', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { title, url, duration, reward, plan_id, status } = req.body;
    
    // Extract YouTube ID to clean up the URL
    let cleanUrl = url;
    if (url && (url.includes('youtube.com') || url.includes('youtu.be'))) {
        const regExp = /^.*(youtu.be\/|v\/|u\/\w\/|embed\/|watch\?v=|&v=)([^#&?]*).*/;
        const match = url.match(regExp);
        if (match && match[2].length === 11) {
            cleanUrl = `https://www.youtube.com/watch?v=${match[2]}`;
        }
    }

    const stmt = db.prepare("UPDATE ads SET title = ?, url = ?, duration = ?, reward = ?, plan_id = ?, status = ? WHERE id = ?");
    stmt.run(title, cleanUrl, duration, reward, plan_id || null, status || 'active', req.params.id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

// Admin API: Get Ads
app.get('/api/admin/ads', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM ads ORDER BY id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Delete Ad
app.delete('/api/admin/ads/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const stmt = db.prepare("DELETE FROM ads WHERE id = ?");
    stmt.run(req.params.id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

// Admin API: Get Users (Including admins, exclude super_admin if needed or just filter in UI)
app.get('/api/admin/users', (req, res) => {
    // Basic session validation
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }

    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }
    
    // Explicitly save session to keep it alive during navigation
    req.session.touch();

    const sql = `
        SELECT 
            u.*,
            p.name AS plan_name
        FROM users u
        LEFT JOIN plans p ON p.id = u.plan_id
        WHERE u.role = 'user'
        ORDER BY u.id DESC
    `;

    db.all(sql, (err, rows) => {
        if (err) {
            console.error("Error fetching users:", err);
            return res.status(500).json({ error: 'DB Error' });
        }
        res.json(rows);
    });
});

// Admin API: Subscription Orders (cross-match with NicePay order number)
app.get('/api/admin/subscription-orders', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }
    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    const q = (req.query.q ? String(req.query.q) : '').trim();
    const limitRaw = req.query.limit !== undefined ? Number(req.query.limit) : 200;
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 200;

    let sql = `
        SELECT
            po.id,
            po.provider,
            po.out_order_number,
            po.status AS order_status,
            po.amount,
            po.created_at,
            po.paid_at,
            po.user_id,
            u.username,
            u.email,
            po.plan_id,
            p.name AS plan_name,
            d.status AS deposit_status,
            d.gateway AS deposit_gateway
        FROM payment_orders po
        JOIN users u ON u.id = po.user_id
        LEFT JOIN plans p ON p.id = po.plan_id
        LEFT JOIN deposits d ON d.transaction_id = po.out_order_number
        WHERE po.order_type = 'subscription'
    `;

    const params = [];
    if (q) {
        sql += ` AND (po.out_order_number LIKE ? OR u.username LIKE ? OR u.email LIKE ?)`;
        const like = `%${q}%`;
        params.push(like, like, like);
    }

    sql += ` ORDER BY po.id DESC LIMIT ?`;
    params.push(limit);

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/admin/subscription-orders/sync', bodyParser.json(), async (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }
    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    const outOrderNumber = (req.body && req.body.out_order_number ? String(req.body.out_order_number) : '').trim();
    if (!outOrderNumber) return res.status(400).json({ error: 'out_order_number is required' });

    const key = (process.env.NICEPAY_KEY || '').trim();
    const merchantId = (process.env.NICEPAY_MERCHANT_ID || '').trim();
    const statusApiUrl = (process.env.NICEPAY_STATUS_API_URL || process.env.NICEPAY_QUERY_API_URL || 'https://api.nicepay.club/v1/orderInfo').trim();

    if (!key || !merchantId || !statusApiUrl) {
        logNicePaySyncHistory({
            outOrderNumber,
            adminId: req.session.user && req.session.user.id,
            adminUsername: req.session.user && req.session.user.username,
            endpoint: statusApiUrl,
            result: 'error',
            responseMsg: 'NicePay status API not configured (missing NICEPAY_KEY / NICEPAY_MERCHANT_ID)'
        });
        return res.status(500).json({ error: 'NicePay status API not configured (missing NICEPAY_KEY / NICEPAY_MERCHANT_ID)' });
    }

    db.get("SELECT * FROM payment_orders WHERE provider = 'nicepay' AND out_order_number = ? AND order_type = 'subscription' LIMIT 1", [outOrderNumber], async (err, order) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!order) return res.status(404).json({ error: 'Order not found' });
        if (String(order.status).toLowerCase() === 'paid') {
            return res.json({ success: true, status: 'paid', message: 'Already paid' });
        }

        const queryParams = {
            out_order_number: outOrderNumber,
            merchant_id: merchantId
        };
        const sign = nicePaySign(queryParams, key);
        const payload = { ...queryParams, sign };

        let providerData = null;
        try {
            const apiRes = await fetch(statusApiUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            providerData = await apiRes.json().catch(() => ({}));
            if (!apiRes.ok) {
                logNicePaySyncHistory({
                    outOrderNumber,
                    adminId: req.session.user && req.session.user.id,
                    adminUsername: req.session.user && req.session.user.username,
                    endpoint: statusApiUrl,
                    result: 'error',
                    responseCode: providerData && providerData.code !== undefined ? providerData.code : null,
                    responseStatus: providerData && providerData.data && providerData.data.status !== undefined ? providerData.data.status : null,
                    responseAmount: providerData && providerData.data && providerData.data.amount !== undefined ? providerData.data.amount : null,
                    responseRealAmount: providerData && providerData.data && providerData.data.real_amount !== undefined ? providerData.data.real_amount : null,
                    responseMsg: providerData && providerData.msg ? providerData.msg : 'NicePay status check failed',
                    responseJson: JSON.stringify(providerData || {})
                });
                return res.status(502).json({ error: 'NicePay status check failed', details: providerData });
            }
        } catch (e) {
            logNicePaySyncHistory({
                outOrderNumber,
                adminId: req.session.user && req.session.user.id,
                adminUsername: req.session.user && req.session.user.username,
                endpoint: statusApiUrl,
                result: 'error',
                responseMsg: 'NicePay status check error'
            });
            return res.status(502).json({ error: 'NicePay status check error' });
        }

        const code = providerData && providerData.code !== undefined && providerData.code !== null ? Number(providerData.code) : null;
        if (code !== 0) {
            const msg = providerData && providerData.msg ? String(providerData.msg) : 'NicePay query failed';
            logNicePaySyncHistory({
                outOrderNumber,
                adminId: req.session.user && req.session.user.id,
                adminUsername: req.session.user && req.session.user.username,
                endpoint: statusApiUrl,
                result: 'error',
                responseCode: code,
                responseMsg: msg,
                responseJson: JSON.stringify(providerData || {})
            });
            return res.status(502).json({ error: msg, details: providerData });
        }

        const body = providerData && providerData.data ? providerData.data : {};
        const paid = isNicePayPaid(body);
        const statusRaw = body && body.status !== undefined && body.status !== null ? String(body.status).trim() : '';
        const realAmount = body && body.real_amount !== undefined && body.real_amount !== null ? Number(body.real_amount) : null;
        const amount = body && body.amount !== undefined && body.amount !== null ? Number(body.amount) : null;
        const finalAmount = Number.isFinite(realAmount) ? realAmount : (Number.isFinite(amount) ? amount : null);

        if (finalAmount !== null && !nicePayAmountMatches(finalAmount, order.amount)) {
            logNicePaySyncHistory({
                outOrderNumber,
                adminId: req.session.user && req.session.user.id,
                adminUsername: req.session.user && req.session.user.username,
                endpoint: statusApiUrl,
                result: 'amount_mismatch',
                responseCode: code,
                responseStatus: statusRaw,
                responseAmount: amount,
                responseRealAmount: realAmount,
                responseMsg: 'Amount mismatch',
                responseJson: JSON.stringify(providerData || {})
            });
            db.run("UPDATE payment_orders SET status = ? WHERE id = ?", ['failed', order.id], () => {
                res.status(409).json({ error: 'Amount mismatch', status: 'failed' });
            });
            return;
        }

        if (!paid) {
            logNicePaySyncHistory({
                outOrderNumber,
                adminId: req.session.user && req.session.user.id,
                adminUsername: req.session.user && req.session.user.username,
                endpoint: statusApiUrl,
                result: statusRaw === '-1' ? 'failed' : 'pending',
                responseCode: code,
                responseStatus: statusRaw,
                responseAmount: amount,
                responseRealAmount: realAmount,
                responseMsg: providerData && providerData.msg ? String(providerData.msg) : '',
                responseJson: JSON.stringify(providerData || {})
            });
            if (statusRaw === '-1') {
                db.run("UPDATE payment_orders SET status = ? WHERE id = ?", ['failed', order.id], () => {
                    res.json({ success: false, status: 'failed' });
                });
                return;
            }
            return res.json({ success: false, status: 'pending' });
        }

        logNicePaySyncHistory({
            outOrderNumber,
            adminId: req.session.user && req.session.user.id,
            adminUsername: req.session.user && req.session.user.username,
            endpoint: statusApiUrl,
            result: 'paid',
            responseCode: code,
            responseStatus: statusRaw,
            responseAmount: amount,
            responseRealAmount: realAmount,
            responseMsg: providerData && providerData.msg ? String(providerData.msg) : '',
            responseJson: JSON.stringify(providerData || {})
        });

        const paidAt = new Date().toISOString();
        db.serialize(() => {
            db.run("UPDATE payment_orders SET status = 'paid', paid_at = ? WHERE id = ?", [paidAt, order.id], () => {
                const depositGateway = 'NicePay Subscription';
                const depositTrx = outOrderNumber;
                db.get("SELECT * FROM deposits WHERE transaction_id = ?", [depositTrx], (e2, existing) => {
                    if (existing && existing.status === 'approved') return res.json({ success: true, status: 'paid', activated: true });

                    db.run(
                        "INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        [order.user_id, order.amount, depositGateway, depositTrx, 'approved', new Date().toISOString(), null],
                        function () {
                            db.get("SELECT duration, daily_limit FROM plans WHERE id = ?", [order.plan_id], (e3, plan) => {
                                if (!plan) return res.json({ success: true, status: 'paid', activated: false });
                                const expiry = new Date(Date.now() + Number(plan.duration) * 24 * 60 * 60 * 1000).toISOString();
                                const startedAt = new Date().toISOString();
                                const totalAds = Number(plan.daily_limit) || 0;
                                db.run(
                                    "UPDATE users SET plan_id = ?, plan_expiry = ?, plan_started_at = ?, plan_ads_used = 0, plan_ads_total = ?, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ?",
                                    [order.plan_id, expiry, startedAt, totalAds, order.user_id],
                                    () => res.json({ success: true, status: 'paid', activated: true })
                                );
                            });
                        }
                    );
                });
            });
        });
    });
});

app.get('/api/admin/subscription-orders/sync-history', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }
    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    const outOrderNumber = (req.query && req.query.out_order_number ? String(req.query.out_order_number) : '').trim();
    if (!outOrderNumber) return res.status(400).json({ error: 'out_order_number is required' });

    db.all(
        "SELECT id, out_order_number, admin_id, admin_username, endpoint, result, response_code, response_status, response_amount, response_real_amount, response_msg, created_at FROM nicepay_sync_history WHERE out_order_number = ? ORDER BY id DESC LIMIT 50",
        [outOrderNumber],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json(Array.isArray(rows) ? rows : []);
        }
    );
});

app.get('/api/admin/nicepay-sync-history', (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }
    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    const q = (req.query.q ? String(req.query.q) : '').trim();
    const limitRaw = req.query.limit !== undefined ? Number(req.query.limit) : 200;
    const limit = Number.isFinite(limitRaw) ? Math.min(Math.max(limitRaw, 1), 1000) : 200;

    let sql = `
        SELECT
            h.id,
            h.out_order_number,
            h.admin_id,
            h.admin_username,
            h.endpoint,
            h.result,
            h.response_code,
            h.response_status,
            h.response_amount,
            h.response_real_amount,
            h.response_msg,
            h.created_at,
            po.user_id,
            u.username AS user_username,
            u.email AS user_email
        FROM nicepay_sync_history h
        LEFT JOIN payment_orders po ON po.out_order_number = h.out_order_number
        LEFT JOIN users u ON u.id = po.user_id
        WHERE 1=1
    `;

    const params = [];
    if (q) {
        sql += ` AND (h.out_order_number LIKE ? OR h.admin_username LIKE ? OR h.result LIKE ? OR h.response_msg LIKE ? OR u.username LIKE ? OR u.email LIKE ?)`;
        const like = `%${q}%`;
        params.push(like, like, like, like, like, like);
    }

    sql += ` ORDER BY id DESC LIMIT ?`;
    params.push(limit);

    db.all(sql, params, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(Array.isArray(rows) ? rows : []);
    });
});

app.post('/api/admin/subscription-orders/activate', bodyParser.json(), (req, res) => {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Unauthorized: Not logged in' });
    }
    if (req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    const outOrderNumber = (req.body && req.body.out_order_number ? String(req.body.out_order_number) : '').trim();
    const planIdRaw = req.body && req.body.plan_id !== undefined && req.body.plan_id !== null ? Number(req.body.plan_id) : null;
    if (!outOrderNumber) return res.status(400).json({ error: 'out_order_number is required' });

    db.get("SELECT * FROM payment_orders WHERE provider = 'nicepay' AND out_order_number = ? AND order_type = 'subscription' LIMIT 1", [outOrderNumber], (err, order) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!order) return res.status(404).json({ error: 'Order not found' });

        const planId = Number.isFinite(planIdRaw) && planIdRaw > 0 ? planIdRaw : Number(order.plan_id);
        if (!Number.isFinite(planId) || planId <= 0) return res.status(400).json({ error: 'Invalid plan_id' });

        db.get("SELECT id, duration, daily_limit FROM plans WHERE id = ? AND status = 'active' LIMIT 1", [planId], (pErr, plan) => {
            if (pErr) return res.status(500).json({ error: 'DB Error' });
            if (!plan) return res.status(404).json({ error: 'Plan not found' });

            const paidAt = new Date().toISOString();
            const depositGateway = 'NicePay Subscription';
            const depositTrx = outOrderNumber;
            const expiry = new Date(Date.now() + Number(plan.duration) * 24 * 60 * 60 * 1000).toISOString();
            const startedAt = new Date().toISOString();
            const totalAds = Number(plan.daily_limit) || 0;

            db.serialize(() => {
                db.run("UPDATE payment_orders SET status = 'paid', paid_at = COALESCE(paid_at, ?), plan_id = ? WHERE id = ?", [paidAt, planId, order.id], () => {
                    db.get("SELECT * FROM deposits WHERE transaction_id = ? LIMIT 1", [depositTrx], (dErr, existing) => {
                        if (dErr) return res.status(500).json({ error: 'DB Error' });

                        const ensureDeposit = (cb) => {
                            if (existing) return cb();
                            db.run(
                                "INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                [order.user_id, order.amount, depositGateway, depositTrx, 'approved', new Date().toISOString(), null],
                                () => cb()
                            );
                        };

                        ensureDeposit(() => {
                            db.run(
                                "UPDATE users SET plan_id = ?, plan_expiry = ?, plan_started_at = ?, plan_ads_used = 0, plan_ads_total = ?, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ?",
                                [planId, expiry, startedAt, totalAds, order.user_id],
                                () => {
                                    logNicePaySyncHistory({
                                        outOrderNumber,
                                        adminId: req.session.user && req.session.user.id,
                                        adminUsername: req.session.user && req.session.user.username,
                                        endpoint: 'manual',
                                        result: 'manual_activate',
                                        responseStatus: 'paid',
                                        responseAmount: Number(order.amount),
                                        responseRealAmount: Number(order.amount),
                                        responseMsg: 'Manual activation'
                                    });
                                    res.json({ success: true, status: 'paid', activated: true });
                                }
                            );
                        });
                    });
                });
            });
        });
    });
});



// Admin API: Get Deposits
app.get('/api/admin/deposits', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT deposits.*, users.username FROM deposits JOIN users ON deposits.user_id = users.id WHERE deposits.status != 'deleted' ORDER BY deposits.id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Delete Deposit (soft delete)
app.delete('/api/admin/deposits/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
    db.run("UPDATE deposits SET status = 'deleted' WHERE id = ?", [id], function (err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Admin API: Get Referrers (Users who have referred others)
app.get('/api/admin/referrers', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const sql = `
        SELECT 
            u.id, 
            u.username, 
            u.email, 
            COUNT(r.id) as referral_count 
        FROM users u 
        JOIN users r ON r.referral = u.username 
        GROUP BY u.id 
        ORDER BY referral_count DESC
    `;
    
    db.all(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Get Detailed Referral Log
app.get('/api/admin/referrals-details', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const sql = `
        SELECT 
            r.id, 
            r.username as referred_user, 
            r.email as referred_email, 
            r.created_at as joined_at,
            u.username as referrer_user
        FROM users r
        JOIN users u ON r.referral = u.username
        ORDER BY r.id DESC
    `;
    
    db.all(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Get Withdrawals
app.get('/api/admin/withdrawals', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT withdrawals.*, users.username FROM withdrawals JOIN users ON withdrawals.user_id = users.id WHERE withdrawals.status != 'deleted' ORDER BY withdrawals.id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Delete Withdrawal (soft delete)
app.delete('/api/admin/withdrawals/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const id = Number(req.params.id);
    if (!Number.isFinite(id) || id <= 0) return res.status(400).json({ error: 'Invalid id' });
    db.run("UPDATE withdrawals SET status = 'deleted' WHERE id = ?", [id], function (err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Admin API: Update Withdrawal Status
app.post('/api/admin/withdrawals/status', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { id, status } = req.body;
    
    db.serialize(() => {
        db.get("SELECT * FROM withdrawals WHERE id = ?", [id], (err, withdrawal) => {
            if (err || !withdrawal) return res.status(404).json({ error: 'Withdrawal not found' });
            
            if (withdrawal.status !== 'pending') {
                return res.status(400).json({ error: 'Request is already processed' });
            }
            
            if (status === 'rejected') {
                // Just update status (No refund needed as balance wasn't deducted)
                db.run("UPDATE withdrawals SET status = 'rejected' WHERE id = ?", [id], (err) => {
                    if (err) return res.status(500).json({ error: 'DB Error updating status' });
                    res.json({ success: true });
                });
            } else if (status === 'approved') {
                // Check balance before approving
                db.get("SELECT balance FROM users WHERE id = ?", [withdrawal.user_id], (err, user) => {
                    if (err) return res.status(500).json({ error: 'DB Error' });
                    if (!user) return res.status(404).json({ error: 'User not found' });

                    if (user.balance < withdrawal.amount) {
                        return res.status(400).json({ error: 'Insufficient user balance for this withdrawal' });
                    }

                    // Deduct balance NOW
                    db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [withdrawal.amount, withdrawal.user_id], (err) => {
                        if (err) return res.status(500).json({ error: 'DB Error deducting balance' });
                        
                        // Update status
                        db.run("UPDATE withdrawals SET status = 'approved' WHERE id = ?", [id], (err) => {
                            if (err) {
                                // Rollback deduction if status update fails
                                db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [withdrawal.amount, withdrawal.user_id]);
                                return res.status(500).json({ error: 'DB Error updating status' });
                            }
                            res.json({ success: true });
                        });
                    });
                });
            } else {
                res.status(400).json({ error: 'Invalid status' });
            }
        });
    });
});

// Admin API: Get KYC Requests
app.get('/api/admin/kyc', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT kyc_requests.*, users.username FROM kyc_requests JOIN users ON kyc_requests.user_id = users.id ORDER BY kyc_requests.id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Update KYC Status
app.post('/api/admin/kyc/status', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { id, status } = req.body;
    
    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ error: 'Invalid status' });
    }

    db.run("UPDATE kyc_requests SET status = ? WHERE id = ?", [status, id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Admin API: Get Support Tickets
app.get('/api/admin/support', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT support_tickets.*, users.username FROM support_tickets JOIN users ON support_tickets.user_id = users.id ORDER BY support_tickets.id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// User API: Get Payment Methods
app.get('/api/payment-methods', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM payment_methods WHERE status = 'active' ORDER BY id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// User API: Manual Subscription (Upload Proof)
app.post('/api/user/subscribe', upload.single('proof'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const userId = req.session.user.id;
    const planId = req.body && req.body.plan_id !== undefined && req.body.plan_id !== null ? Number(req.body.plan_id) : null;
    const methodId = req.body && req.body.method_id !== undefined && req.body.method_id !== null ? Number(req.body.method_id) : null;
    const proofImage = req.file ? '/uploads/' + req.file.filename : null;

    if (!Number.isFinite(planId) || planId <= 0) return res.status(400).json({ error: 'Invalid plan' });
    if (!Number.isFinite(methodId) || methodId <= 0) return res.status(400).json({ error: 'Invalid payment method' });
    if (!proofImage) return res.status(400).json({ error: 'Payment proof is required' });

    db.get("SELECT id, name, price FROM plans WHERE id = ? AND status = 'active' LIMIT 1", [planId], (pErr, plan) => {
        if (pErr || !plan) return res.status(400).json({ error: 'Plan not found' });

        db.get("SELECT id, name, min_amount, max_amount, status FROM payment_methods WHERE id = ? AND status = 'active' LIMIT 1", [methodId], (mErr, method) => {
            if (mErr || !method) return res.status(400).json({ error: 'Invalid payment method' });

            const amount = Number(plan.price) || 0;
            const minAmount = Number(method.min_amount) || 0;
            const maxAmount = Number(method.max_amount) || 0;
            if (amount <= 0) return res.status(400).json({ error: 'Plan price invalid' });
            if (minAmount > 0 && amount < minAmount) return res.status(400).json({ error: `Amount must be at least ${minAmount}` });
            if (maxAmount > 0 && amount > maxAmount) return res.status(400).json({ error: `Amount must be at most ${maxAmount}` });

            const transactionId = `SUB-${planId}-${Date.now()}-${userId}`;
            const gateway = `Manual Subscription (${method.name})`;

            const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)");
            stmt.run(userId, amount, gateway, transactionId, 'pending', new Date().toISOString(), proofImage, function (iErr) {
                if (iErr) {
                    console.error(iErr);
                    return res.status(500).json({ error: 'DB Error' });
                }
                res.json({ success: true, transaction_id: transactionId });
            });
            stmt.finalize();
        });
    });
});

// User API: Submit Deposit (Disabled)
/* app.post('/api/user/deposit', upload.single('proof'), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    const { method_id, amount } = req.body;
    const proof_image = req.file ? '/uploads/' + req.file.filename : null;
    
    // Validate method
    db.get("SELECT * FROM payment_methods WHERE id = ? AND status = 'active'", [method_id], (err, method) => {
        if (err || !method) return res.status(400).json({ error: 'Invalid payment method' });
        
        // Validate limits
        if (amount < method.min_amount || amount > method.max_amount) {
            return res.status(400).json({ error: `Amount must be between ${method.min_amount} and ${method.max_amount}` });
        }

        // Generate a transaction ID since user input is removed
        const transaction_id = 'DEP-' + Date.now() + '-' + Math.floor(Math.random() * 1000);

        const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at, proof_image) VALUES (?, ?, ?, ?, ?, ?, ?)");
        stmt.run(req.session.user.id, amount, method.name, transaction_id, 'pending', new Date().toISOString(), proof_image, function(err) {
            if (err) {
                console.error(err);
                return res.status(500).json({ error: 'DB Error' });
            }
            res.json({ success: true });
        });
        stmt.finalize();
    });
}); */

// User API: Get Transactions
app.get('/api/user/transactions', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Unauthorized' });
    }
    
    // Union deposits and withdrawals
    const userId = req.session.user.id;
    db.all(`
        SELECT 
            id, 
            transaction_id as trx, 
            amount, 
            0 as charge, 
            status, 
            gateway as method, 
            'Deposit' as type,
            created_at
        FROM deposits 
        WHERE user_id = ? 
        
        UNION ALL
        
        SELECT 
            id, 
            'WD-' || id || '-' || strftime('%s', created_at) as trx, 
            amount, 
            0 as charge, 
            status, 
            method, 
            'Withdraw' as type, 
            created_at
        FROM withdrawals 
        WHERE user_id = ? 
        
        UNION ALL

        SELECT 
            id, 
            'TRF-' || id || '-' || strftime('%s', created_at) as trx, 
            amount, 
            0 as charge, 
            'completed' as status, 
            'Internal Transfer' as method, 
            CASE WHEN sender_id = ? THEN 'Transfer Sent' ELSE 'Transfer Received' END as type,
            created_at
        FROM transfers 
        WHERE sender_id = ? OR receiver_id = ?

        ORDER BY created_at DESC
    `, [userId, userId, userId, userId, userId], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// User API: Redeem Rewards
app.post('/api/user/redeem-rewards', bodyParser.json(), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    const userId = req.session.user.id;
    
    db.serialize(() => {
        // 1. Check Reward Balance
        db.get("SELECT reward_balance FROM users WHERE id = ?", [userId], (err, row) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            
            const rewardBalance = row ? row.reward_balance : 0;
            
            if (rewardBalance <= 0) {
                return res.status(400).json({ error: 'No rewards to redeem' });
            }
            
            // 2. Transfer to Main Balance
            // Deduct from reward_balance
            db.run("UPDATE users SET reward_balance = 0 WHERE id = ?", [userId], (err) => {
                if (err) return res.status(500).json({ error: 'DB Error deducting rewards' });
                
                // Add to main balance
                db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [rewardBalance, userId], (err) => {
                    if (err) {
                        // Rollback (simplified, ideally use transactions)
                        db.run("UPDATE users SET reward_balance = ? WHERE id = ?", [rewardBalance, userId]);
                        return res.status(500).json({ error: 'DB Error adding balance' });
                    }
                    
                    // 3. Log Transaction (Redemption)
                    const trxId = `REDEEM-${userId}-${Date.now()}`;
                    const stmt = db.prepare("INSERT INTO deposits (user_id, amount, gateway, transaction_id, status, created_at) VALUES (?, ?, ?, ?, 'completed', ?)");
                    stmt.run(userId, rewardBalance, 'Reward Redemption', trxId, new Date().toISOString(), function(err) {
                        if (err) console.error("Error logging redemption:", err);
                        res.json({ success: true, amount: rewardBalance });
                    });
                    stmt.finalize();
                });
            });
        });
    });
});

// User API: Get Rewards History
app.get('/api/user/rewards-history', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    const userId = req.session.user.id;
    
    db.serialize(() => {
        const history = {};
        
        // 1. Earnings (Bonuses/Commissions)
        db.all("SELECT * FROM deposits WHERE user_id = ? AND gateway IN ('Referral Bonus','Referral Commission') ORDER BY id DESC", [userId], (err, earnings) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            history.earnings = earnings;
            
            // 2. Redemptions - Look for gateway 'Reward Redemption'
            db.all("SELECT * FROM deposits WHERE user_id = ? AND gateway = 'Reward Redemption' ORDER BY id DESC", [userId], (err, redemptions) => {
                if (err) return res.status(500).json({ error: 'DB Error' });
                history.redemptions = redemptions;
                
                res.json(history);
            });
        });
    });
});

// User API: Get Referrals
app.get('/api/user/referrals', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });

    const referrerId = req.session.user.id;

    db.get("SELECT value FROM settings WHERE key = 'referral_signup_bonus'", (bErr, bRow) => {
        const configuredBonus = !bErr && bRow && bRow.value !== undefined && bRow.value !== null ? Number(bRow.value) || 0 : 0;

        db.all("SELECT id, username, email, created_at, plan_id FROM users WHERE referral = ? ORDER BY id DESC", [req.session.user.username], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });

            const promises = (rows || []).map(row => {
                return new Promise((resolve) => {
                    const out = { ...row, configured_bonus: configuredBonus };

                    const finish = () => {
                        const pattern = `REFERRAL-BONUS-${referrerId}-${row.id}-%`;
                        db.get(
                            "SELECT amount, transaction_id, created_at FROM deposits WHERE user_id = ? AND gateway = 'Referral Bonus' AND transaction_id LIKE ? ORDER BY id DESC LIMIT 1",
                            [referrerId, pattern],
                            (tErr, trx) => {
                                if (!tErr && trx) {
                                    out.bonus_amount = Number(trx.amount) || 0;
                                    out.bonus_transaction_id = trx.transaction_id;
                                    out.bonus_created_at = trx.created_at;
                                    out.bonus_status = 'credited';
                                } else {
                                    out.bonus_amount = 0;
                                    out.bonus_transaction_id = null;
                                    out.bonus_created_at = null;
                                    out.bonus_status = 'not_credited';
                                }
                                resolve(out);
                            }
                        );
                    };

                    if (row.plan_id) {
                        db.get("SELECT name FROM plans WHERE id = ?", [row.plan_id], (pErr, plan) => {
                            out.plan_name = !pErr && plan ? plan.name : 'No Plan';
                            finish();
                        });
                    } else {
                        out.plan_name = 'No Plan';
                        finish();
                    }
                });
            });

            Promise.all(promises).then(enrichedRows => res.json(enrichedRows));
        });
    });
});

// Admin API: Update Deposit Status
app.post('/api/admin/deposits/status', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const { id, status } = req.body;
    
    // Start a transaction-like sequence
    db.serialize(() => {
        db.get("SELECT * FROM deposits WHERE id = ?", [id], (err, deposit) => {
            if (err || !deposit) return res.status(404).json({ error: 'Deposit not found' });
            
            if (deposit.status === 'approved') {
                return res.status(400).json({ error: 'Already approved' });
            }
            
            if (status === 'approved') {
                // Update deposit status
                db.run("UPDATE deposits SET status = 'approved' WHERE id = ?", [id], (err) => {
                    if (err) return res.status(500).json({ error: 'DB Error updating deposit' });
                    
                    // Double Profit manual payment: unlock DP purchase (do NOT add balance)
                    if (deposit.transaction_id && deposit.transaction_id.startsWith('DP-')) {
                        const paidAt = new Date().toISOString();
                        db.run(
                            "UPDATE double_profit_offer_purchases SET payment_status = 'paid', paid_at = COALESCE(paid_at, ?) WHERE out_order_number = ? AND user_id = ? AND payment_status != 'paid'",
                            [paidAt, deposit.transaction_id, deposit.user_id],
                            () => res.json({ success: true })
                        );
                        return;
                    }

                    // Check if this is a Subscription Request (Starts with SUB-)
                    if (deposit.transaction_id && deposit.transaction_id.startsWith('SUB-')) {
                        // Extract Plan ID
                        const parts = deposit.transaction_id.split('-');
                        const planId = parseInt(parts[1]);
                        
                        if (planId) {
                            // Get Plan Duration
                            db.get("SELECT duration, daily_limit FROM plans WHERE id = ?", [planId], (err, plan) => {
                                if (err || !plan) {
                                    console.error("Plan not found for approved subscription:", planId);
                                    return res.json({ success: true, warning: 'Plan not found, but status updated.' });
                                }
                                
                                // Activate Plan for User (Without adding balance)
                                const expiry = new Date(Date.now() + plan.duration * 24 * 60 * 60 * 1000).toISOString();
                                const startedAt = new Date().toISOString();
                                const totalAds = Number(plan.daily_limit) || 0;
                                db.run("UPDATE users SET plan_id = ?, plan_expiry = ?, plan_started_at = ?, plan_ads_used = 0, plan_ads_total = ?, double_profit_unlocked = 0, double_profit_bonus_pct = 0, double_profit_unlocked_at = NULL WHERE id = ?", [planId, expiry, startedAt, totalAds, deposit.user_id], (err) => {
                                    if (err) console.error("Error activating plan:", err);

                                    res.json({ success: true });
                                });
                            });
                        } else {
                            res.json({ success: true });
                        }
                    } else {
                        // Normal Deposit: Add balance to user
                        db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [deposit.amount, deposit.user_id], (err) => {
                            if (err) console.error("Error adding balance after deposit approval:", err);
                            awardReferralDepositCommission({ referredUserId: deposit.user_id, depositAmount: deposit.amount, sourceTransactionId: deposit.transaction_id });
                            res.json({ success: true });
                        });
                    }
                });
            } else {
                // Just update status (e.g. rejected)
                db.run("UPDATE deposits SET status = ? WHERE id = ?", [status, id], (err) => {
                    if (err) return res.status(500).json({ error: 'DB Error' });
                    res.json({ success: true });
                });
            }
        });
    });
});

// Admin API: Plans
app.get('/api/admin/plans', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM plans ORDER BY price ASC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/admin/plans', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, description, price, duration, daily_limit, withdraw_limit, estimated_profit, status, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct } = req.body;
    
    const stmt = db.prepare("INSERT INTO plans (name, description, price, duration, daily_limit, withdraw_limit, estimated_profit, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    stmt.run(name, description, price, duration, daily_limit, withdraw_limit || 0, estimated_profit || '', double_profit_after_ads || 0, double_profit_fee || 0, double_profit_bonus_pct || 0, status || 'active', new Date().toISOString(), function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

app.put('/api/admin/plans/:id', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, description, price, duration, daily_limit, withdraw_limit, estimated_profit, status, double_profit_after_ads, double_profit_fee, double_profit_bonus_pct } = req.body;
    
    const stmt = db.prepare("UPDATE plans SET name = ?, description = ?, price = ?, duration = ?, daily_limit = ?, withdraw_limit = ?, estimated_profit = ?, double_profit_after_ads = ?, double_profit_fee = ?, double_profit_bonus_pct = ?, status = ? WHERE id = ?");
    stmt.run(name, description, price, duration, daily_limit, withdraw_limit || 0, estimated_profit || '', double_profit_after_ads || 0, double_profit_fee || 0, double_profit_bonus_pct || 0, status, req.params.id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

app.delete('/api/admin/plans/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.run("DELETE FROM plans WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

app.get('/api/admin/plans/:id/double-profit-offers', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const planId = Number(req.params.id);
    if (!Number.isFinite(planId) || planId <= 0) return res.status(400).json({ error: 'Invalid plan id' });

    db.all(
        "SELECT id, plan_id, after_ads, fee, bonus_pct, status, created_at FROM double_profit_offers WHERE plan_id = ? ORDER BY after_ads ASC, id ASC",
        [planId],
        (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json(Array.isArray(rows) ? rows : []);
        }
    );
});

app.put('/api/admin/plans/:id/double-profit-offers', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const planId = Number(req.params.id);
    if (!Number.isFinite(planId) || planId <= 0) return res.status(400).json({ error: 'Invalid plan id' });

    const offers = Array.isArray(req.body && req.body.offers) ? req.body.offers : [];
    const cleaned = offers
        .map(o => ({
            after_ads: Number(o && o.after_ads),
            fee: Number(o && o.fee),
            bonus_pct: Number(o && o.bonus_pct),
            status: (o && o.status ? String(o.status) : 'active').toLowerCase()
        }))
        .filter(o => Number.isFinite(o.after_ads) && o.after_ads > 0 && Number.isFinite(o.fee) && o.fee > 0 && Number.isFinite(o.bonus_pct) && o.bonus_pct > 0)
        .slice(0, 50);

    db.serialize(() => {
        db.run("DELETE FROM double_profit_offers WHERE plan_id = ?", [planId], (dErr) => {
            if (dErr) return res.status(500).json({ error: 'DB Error' });
            if (!cleaned.length) return res.json({ success: true });

            const stmt = db.prepare("INSERT INTO double_profit_offers (plan_id, after_ads, fee, bonus_pct, status, created_at) VALUES (?, ?, ?, ?, ?, ?)");
            const now = new Date().toISOString();
            cleaned.forEach(o => {
                const st = (o.status === 'inactive' ? 'inactive' : 'active');
                stmt.run(planId, o.after_ads, o.fee, o.bonus_pct, st, now);
            });
            stmt.finalize((fErr) => {
                if (fErr) return res.status(500).json({ error: 'DB Error' });
                res.json({ success: true });
            });
        });
    });
});

// User API: Reviews
app.get('/api/reviews', (req, res) => {
    db.all("SELECT * FROM reviews WHERE is_approved = 1 ORDER BY id DESC LIMIT 300", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/reviews', bodyParser.json(), (req, res) => {
    const { username, language, content } = req.body;
    if (!username || !content) return res.status(400).json({ error: 'Missing required fields' });
    
    const stmt = db.prepare("INSERT INTO reviews (username, language, content, created_at, is_approved) VALUES (?, ?, ?, ?, ?)");
    stmt.run(username, language || 'en', content, new Date().toISOString(), 0, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

// Admin API: Reviews
app.get('/api/admin/reviews', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM reviews ORDER BY id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/admin/reviews', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { username, language, content, is_approved } = req.body;
    
    const stmt = db.prepare("INSERT INTO reviews (username, language, content, created_at, is_approved) VALUES (?, ?, ?, ?, ?)");
    stmt.run(username, language || 'en', content, new Date().toISOString(), is_approved !== undefined ? is_approved : 1, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

app.put('/api/admin/reviews/:id', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const id = req.params.id;
    const { is_approved } = req.body;
    
    const stmt = db.prepare("UPDATE reviews SET is_approved = ? WHERE id = ?");
    stmt.run(is_approved, id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

app.delete('/api/admin/reviews/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const id = req.params.id;
    
    db.run("DELETE FROM reviews WHERE id = ?", [id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

app.post('/api/admin/reviews/seed', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    
    const englishReviews = [
        "Amazing platform, highly recommended!", "Fast withdrawals and great support.", "Best investment site I have ever used.",
        "Very reliable and trustworthy.", "I made a good profit here, thanks!", "Customer service is top notch.",
        "Easy to use interface.", "I love the referral program.", "Smooth transactions every time.", "Will definitely invest more."
    ];
    const urduReviews = [
        "Bohat achi website hai, zaroor try karein.", "Withdrawal jaldi mil jata hai.", "Bhtrin platform profit ke liye.",
        "Bharosemand aur asan.", "Mera tajurba bohat acha raha.", "Customer support bohat co-operative hai.",
        "Asan istemal.", "Referral program bohat munasib hai.", "Transactions bina kisi masle ke hoti hain.", "Main mazeed invest karunga."
    ];
    
    const names = ["Ali", "Sarah", "Ahmed", "Ayesha", "John", "Fatima", "Usman", "Zainab", "Hassan", "Khadija"];
    
    db.serialize(() => {
        const stmt = db.prepare("INSERT INTO reviews (username, language, content, created_at, is_approved) VALUES (?, ?, ?, ?, ?)");
        
        for (let i = 0; i < 300; i++) {
            const isEnglish = Math.random() > 0.5;
            const lang = isEnglish ? 'en' : 'ur';
            const contentPool = isEnglish ? englishReviews : urduReviews;
            
            const username = names[Math.floor(Math.random() * names.length)] + Math.floor(Math.random() * 1000);
            const content = contentPool[Math.floor(Math.random() * contentPool.length)];
            
            stmt.run(username, lang, content, new Date().toISOString(), 1);
        }
        stmt.finalize((err) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json({ success: true, message: '300 reviews seeded successfully' });
        });
    });
});

// User API: Get Plans
app.get('/api/plans', (req, res) => {
    db.all("SELECT * FROM plans WHERE status = 'active' ORDER BY price ASC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Portfolios
app.get('/api/admin/portfolios', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM portfolios ORDER BY level ASC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/admin/portfolios', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, level, min_transactions, bonus, description, status } = req.body;
    
    const stmt = db.prepare("INSERT INTO portfolios (name, level, min_transactions, bonus, description, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)");
    stmt.run(name, level, min_transactions, bonus, description, status || 'active', new Date().toISOString(), function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

app.put('/api/admin/portfolios/:id', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, level, min_transactions, bonus, description, status } = req.body;
    
    const stmt = db.prepare("UPDATE portfolios SET name = ?, level = ?, min_transactions = ?, bonus = ?, description = ?, status = ? WHERE id = ?");
    stmt.run(name, level, min_transactions, bonus, description, status, req.params.id, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

app.delete('/api/admin/portfolios/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.run("DELETE FROM portfolios WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// User API: Get Portfolios
app.get('/api/portfolios', (req, res) => {
    db.all("SELECT * FROM portfolios WHERE status = 'active' ORDER BY level ASC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// Admin API: Payment Methods
app.get('/api/admin/payment-methods', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.all("SELECT * FROM payment_methods ORDER BY id DESC", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

app.post('/api/admin/payment-methods', upload.single('image'), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, account_number, bank_name, currency, rate, min_amount, max_amount, instructions, status } = req.body;
    const image_path = req.file ? '/uploads/' + req.file.filename : null;
    
    const stmt = db.prepare("INSERT INTO payment_methods (name, account_number, bank_name, currency, rate, min_amount, max_amount, instructions, image_path, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    stmt.run(name, account_number, bank_name, currency, rate, min_amount, max_amount, instructions, image_path, status || 'active', new Date().toISOString(), function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'DB Error' });
        }
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

app.put('/api/admin/payment-methods/:id', upload.single('image'), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { name, account_number, bank_name, currency, rate, min_amount, max_amount, instructions, status } = req.body;
    const image_path = req.file ? '/uploads/' + req.file.filename : undefined;

    let sql = "UPDATE payment_methods SET name = ?, account_number = ?, bank_name = ?, currency = ?, rate = ?, min_amount = ?, max_amount = ?, instructions = ?, status = ?";
    let params = [name, account_number, bank_name, currency, rate, min_amount, max_amount, instructions, status];

    if (image_path) {
        sql += ", image_path = ?";
        params.push(image_path);
    }
    sql += " WHERE id = ?";
    params.push(req.params.id);

    const stmt = db.prepare(sql);
    stmt.run(...params, function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

app.delete('/api/admin/payment-methods/:id', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    db.run("DELETE FROM payment_methods WHERE id = ?", [req.params.id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    db.get("SELECT * FROM users WHERE username = ? AND password = ? AND role = 'admin'", [username, password], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (row) {
            req.session.user = row;
            res.json({ success: true, redirect: '/admin_dashboard.html' });
        } else {
            res.status(401).json({ error: 'Invalid admin credentials' });
        }
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const cleanEmail = String(email || '').trim();
    db.get("SELECT * FROM users WHERE LOWER(email) = LOWER(?) AND password = ?", [cleanEmail, password], (err, row) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (row) {
            if (Number(row.is_banned) === 1) {
                return res.status(403).json({ error: 'Your account is banned. Contact customer service.' });
            }
            req.session.user = row;
            res.json({ success: true, redirect: '/dashboard.html' });
        } else {
            res.status(401).json({ error: 'Invalid email or password' });
        }
    });
});

app.get('/dashboard.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'dashboard.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/register', (req, res) => {
    const idx = req.originalUrl.indexOf('?');
    const qs = idx !== -1 ? req.originalUrl.slice(idx) : '';
    res.redirect(`/register.html${qs}`);
});

app.get('/subscriptions.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'subscriptions.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/community.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'community.html'));
    } else {
        res.redirect('/login.html');
    }
});

/* app.get('/deposit.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'deposit.html'));
    } else {
        res.redirect('/login.html');
    }
}); */

app.get('/fund_transfer.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'fund_transfer.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/ads.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'ads.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/transactions.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'transactions.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/withdraw.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'withdraw.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/referral.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'referral.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/portfolios.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'portfolios.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/support.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'support.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/rewards.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'rewards.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/settings.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'settings.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/change_password.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'change_password.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/verification.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'verification.html'));
    } else {
        res.redirect('/login.html');
    }
});

app.get('/id_card_form.html', (req, res) => {
    if (req.session.user) {
        res.sendFile(path.join(__dirname, 'id_card_form.html'));
    } else {
        res.redirect('/login.html');
    }
});

// API endpoint to change password without old password check
app.post('/api/change-password', bodyParser.json(), (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not logged in' });
    }

    const { newPassword } = req.body;
    if (!newPassword) {
        return res.status(400).json({ error: 'New password is required' });
    }

    const stmt = db.prepare("UPDATE users SET password = ? WHERE id = ?");
    stmt.run(newPassword, req.session.user.id, function(err) {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ success: true });
    });
    stmt.finalize();
});

// API endpoint to get current user info for frontend scripts
app.get('/api/user-info', (req, res) => {
    // Prevent caching
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');

    if (req.session.user) {
        // Fetch fresh data from DB to ensure we have all fields including balance and plan info
        db.get(`
            SELECT users.id, users.firstname, users.lastname, users.username, users.email, users.country, users.phone, users.referral, users.gender, users.address, users.city, users.zip, users.dob, users.created_at, users.balance, users.reward_balance, users.plan_id, users.plan_expiry, users.role, users.is_banned, plans.name as plan_name 
            FROM users 
            LEFT JOIN plans ON users.plan_id = plans.id 
            WHERE users.id = ?
        `, [req.session.user.id], (err, row) => {
            if (err) {
                console.error("Error fetching user info:", err);
                res.status(500).json({ error: 'Database error' });
            } else if (row) {
                if (!req.session.adminId && Number(row.is_banned) === 1) {
                    return req.session.destroy(() => res.status(403).json({ error: 'Your account is banned. Contact customer service.' }));
                }
                // Update session with fresh data to keep it in sync
                const adminId = req.session.adminId; // Preserve adminId if it exists
                req.session.user = row;
                if (adminId) req.session.adminId = adminId;

                console.log(`User Info Request: User ${row.id} (${row.username}), Balance: ${row.balance}`);

                // Include adminId status so frontend can show "Switch Back" button
                if (req.session.adminId) {
                    row.isAdminImpersonating = true;
                }
                
                // Fetch KYC status
                db.get("SELECT status FROM kyc_requests WHERE user_id = ? ORDER BY id DESC LIMIT 1", [req.session.user.id], (err, kyc) => {
                    if (!err && kyc) {
                        row.kyc_status = kyc.status;
                    } else {
                        row.kyc_status = 'pending_submission'; // or null
                    }
                    
                    // --- NEW: Add Real-Time Stats for Dashboard Boxes ---
                    db.serialize(() => {
                        // 1. Viewed Ads Count
                        db.get("SELECT COUNT(*) as count FROM deposits WHERE user_id = ? AND gateway = 'Ad View'", [req.session.user.id], (err, adRow) => {
                            row.viewedAdsCount = adRow ? adRow.count : 0;

                            // 2. Total Transactions Count
                            db.get("SELECT (SELECT COUNT(*) FROM deposits WHERE user_id = ?) + (SELECT COUNT(*) FROM withdrawals WHERE user_id = ?) as total", [req.session.user.id, req.session.user.id], (err, trxRow) => {
                                row.totalTransactions = trxRow ? trxRow.total : 0;

                                // 3. Total Earnings (Ad Views ONLY as per user request)
                                // Note: Referral bonuses are now in Reward Balance, not counted here until redeemed.
                                db.get("SELECT SUM(amount) as total FROM deposits WHERE user_id = ? AND gateway = 'Ad View'", [req.session.user.id], (err, earnRow) => {
                                    row.totalEarnings = earnRow && earnRow.total ? earnRow.total : 0;

                                    // 4. Total Referrals Count
                                    db.get("SELECT COUNT(*) as count FROM users WHERE referral = ?", [req.session.user.username], (err, refRow) => {
                                        row.referralCount = refRow ? refRow.count : 0;

                                        // 5. Total Withdrawals Amount
                                        db.get("SELECT SUM(amount) as total FROM withdrawals WHERE user_id = ? AND status = 'approved'", [req.session.user.id], (err, wdRow) => {
                                            row.totalWithdraw = wdRow && wdRow.total ? wdRow.total : 0;

                                            // 6. Support Tickets Count
                                            db.get("SELECT COUNT(*) as count FROM support_tickets WHERE user_id = ?", [req.session.user.id], (err, tickRow) => {
                                                row.ticketCount = tickRow ? tickRow.count : 0;

                                                // Send Final Response with all stats
                                                res.json(row);
                                            });
                                        });
                                    });
                                });
                            });
                        });
                    });
                    // ----------------------------------------------------
                });
            } else {
                res.status(404).json({ error: 'User not found' });
            }
        });
    } else {
        res.status(401).json({ error: 'Not logged in' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/login.html');
});

// Admin Logout
app.get('/admin/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/admin_login.html');
});

// --- Customer Service / Live Chat APIs ---

// 1. Get Contact Settings (Public)
app.get('/api/settings/contact', (req, res) => {
    db.all("SELECT key, value FROM settings WHERE key IN ('telegram_link', 'whatsapp_link')", (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        const settings = {};
        rows.forEach(row => settings[row.key] = row.value);
        res.json(settings);
    });
});

// 2. Save Contact Settings (Admin)
app.post('/api/admin/settings/contact', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') {
        return res.status(403).json({ error: 'Unauthorized' });
    }
    const { telegram_link, whatsapp_link } = req.body;
    
    db.serialize(() => {
        const stmt = db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)");
        stmt.run('telegram_link', telegram_link);
        stmt.run('whatsapp_link', whatsapp_link);
        stmt.finalize();
        res.json({ success: true });
    });
});

// 3. Get User Chat History (User)
app.get('/api/chat', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    db.all("SELECT * FROM chat_messages WHERE user_id = ? ORDER BY created_at ASC", [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// 4. Send Message (User)
app.post('/api/chat', bodyParser.json(), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    const { message } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });

    const stmt = db.prepare("INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, 'user', ?, ?)");
    stmt.run(req.session.user.id, message, new Date().toISOString(), function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true, id: this.lastID });
    });
    stmt.finalize();
});

// 5. Get All Chats (Admin - Grouped by User)
app.get('/api/admin/chats', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });

    // Get list of users who have chatted, with last message
    const sql = `
        SELECT 
            u.id, u.username, u.firstname, u.lastname,
            MAX(cm.created_at) as last_activity,
            (SELECT COUNT(*) FROM chat_messages WHERE user_id = u.id AND sender = 'user' AND is_read = 0) as unread_count
        FROM chat_messages cm
        JOIN users u ON cm.user_id = u.id
        GROUP BY cm.user_id
        ORDER BY last_activity DESC
    `;
    db.all(sql, (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// 6. Get Specific User Chat (Admin)
app.get('/api/admin/chat/:userId', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    const userId = req.params.userId;
    
    // Mark as read first
    db.run("UPDATE chat_messages SET is_read = 1 WHERE user_id = ? AND sender = 'user'", [userId], (err) => {
        if (err) console.error("Error marking read:", err);
        
        // Fetch messages
        db.all("SELECT * FROM chat_messages WHERE user_id = ? ORDER BY created_at ASC", [userId], (err, rows) => {
            if (err) return res.status(500).json({ error: 'DB Error' });
            res.json(rows);
        });
    });
});

// 7. Send Message (Admin)
app.post('/api/admin/chat', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    const { userId, message } = req.body;
    if (!userId || !message) return res.status(400).json({ error: 'Missing data' });

    const stmt = db.prepare("INSERT INTO chat_messages (user_id, sender, message, created_at) VALUES (?, 'admin', ?, ?)");
    stmt.run(userId, message, new Date().toISOString(), function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

// 8. Delete User Chat History (Admin)
app.delete('/api/admin/chat/:userId', (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    const userId = req.params.userId;
    db.run("DELETE FROM chat_messages WHERE user_id = ?", [userId], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// User API: Create Support Ticket
app.post('/api/user/ticket', upload.single('image'), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    const { subject, priority, message } = req.body;
    // image is optional
    
    const stmt = db.prepare("INSERT INTO support_tickets (user_id, subject, priority, message, status, created_at) VALUES (?, ?, ?, ?, 'open', ?)");
    stmt.run(req.session.user.id, subject, priority, message, new Date().toISOString(), function(err) {
        if (err) {
            console.error(err);
            return res.status(500).json({ error: 'DB Error' });
        }
        res.json({ success: true });
    });
    stmt.finalize();
});

// User API: Get My Tickets
app.get('/api/user/tickets', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    db.all("SELECT * FROM support_tickets WHERE user_id = ? ORDER BY id DESC", [req.session.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// API: Get Ticket Details
app.get('/api/tickets/:id', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    const ticketId = req.params.id;
    const userId = req.session.user.id;
    const isAdmin = req.session.user.role === 'admin';

    let sql = "SELECT support_tickets.*, users.username FROM support_tickets JOIN users ON support_tickets.user_id = users.id WHERE support_tickets.id = ?";
    let params = [ticketId];

    // If not admin, restrict to own tickets
    if (!isAdmin) {
        sql += " AND support_tickets.user_id = ?";
        params.push(userId);
    }

    db.get(sql, params, (err, row) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        if (!row) return res.status(404).json({ error: 'Ticket not found' });
        res.json(row);
    });
});

// API: Get Ticket Replies
app.get('/api/tickets/:id/replies', (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    // We don't strictly check ownership here for simplicity, assuming the UI handles it, 
    // but in production, we should verify the user owns the ticket or is admin.
    db.all("SELECT * FROM ticket_replies WHERE ticket_id = ? ORDER BY created_at ASC", [req.params.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json(rows);
    });
});

// API: Post Reply
app.post('/api/tickets/:id/reply', bodyParser.json(), (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Unauthorized' });
    
    const ticketId = req.params.id;
    const { message } = req.body;
    const sender = req.session.user.role === 'admin' ? 'Admin' : 'User';

    if (!message) return res.status(400).json({ error: 'Message required' });

    const stmt = db.prepare("INSERT INTO ticket_replies (ticket_id, sender, message, created_at) VALUES (?, ?, ?, ?)");
    stmt.run(ticketId, sender, message, new Date().toISOString(), function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
    stmt.finalize();
});

// Admin API: Update Ticket Status
app.post('/api/admin/tickets/status', bodyParser.json(), (req, res) => {
    if (!req.session.user || req.session.user.role !== 'admin') return res.status(403).json({ error: 'Unauthorized' });
    
    const { id, status } = req.body;
    if (!['open', 'closed'].includes(status)) return res.status(400).json({ error: 'Invalid status' });

    db.run("UPDATE support_tickets SET status = ? WHERE id = ?", [status, id], function(err) {
        if (err) return res.status(500).json({ error: 'DB Error' });
        res.json({ success: true });
    });
});

// Start server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
