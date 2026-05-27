const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 4321;
const JWT_SECRET = process.env.JWT_SECRET || 'philippine-law-search-super-secret-key-2026';

// Cloudflare KV Sync settings
const CLOUDFLARE_WORKER_URL = 'https://sc-search-api.hindipogi.workers.dev';
const CLOUDFLARE_ADMIN_SECRET = 'philippine-law-admin-sync-secret-2026';

// Database paths - use persistent disk on Render (/data) or local fallback
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FREE_PATH = path.join(DATA_DIR, 'jurisprudence_free.db');
const DB_PREMIUM_PATH = path.join(DATA_DIR, 'db_classic.db');
const DB_SEARCH_PATH = path.join(DATA_DIR, 'db_recent.db');   // Full 1901–2026 search index
const DB_STATUTES_PATH = path.join(DATA_DIR, 'db_statutes.db');
const USERS_DB_PATH = path.join(DATA_DIR, 'users.db');

// CORS: Allow frontend from Cloudflare Pages
app.use(cors({
    origin: [
        'https://scjurisph.pages.dev',
        'https://sc-law-search.pages.dev',
        /\.scjurisph\.pages\.dev$/,
        /\.sc-law-search\.pages\.dev$/,
        'http://localhost:4321',
        'http://localhost:3000',
        'http://127.0.0.1:4321',
        'http://localhost:7777'
    ],
    credentials: true
}));

app.use(express.json());

// Health check endpoint for Render
app.get('/', (req, res) => {
    res.json({ 
        status: 'ok', 
        service: 'SCJurisPH API',
        databases: {
            search: fs.existsSync(DB_SEARCH_PATH),   // db_recent.db - 1901 to 2026
            free: fs.existsSync(DB_FREE_PATH),
            premium: fs.existsSync(DB_PREMIUM_PATH),
            statutes: fs.existsSync(DB_STATUTES_PATH),
            users: fs.existsSync(USERS_DB_PATH)
        }
    });
});

// Initialize Users Database
function initUsersDb() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT DEFAULT 'free',
                current_token_jti TEXT
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS folders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        `);
        db.run(`
            CREATE TABLE IF NOT EXISTS bookmarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                folder_name TEXT,
                item_id TEXT NOT NULL,
                item_type TEXT DEFAULT 'jurisprudence',
                title TEXT,
                reference_num TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(folder_id) REFERENCES folders(id)
            )
        `);
        // Add folder_name column to existing bookmarks table if missing (migration)
        db.run(`ALTER TABLE bookmarks ADD COLUMN folder_name TEXT`, () => {});
        // Ensure item_id is TEXT (old schema used INTEGER) - handled by loose SQLite typing
        db.run(`
            CREATE TABLE IF NOT EXISTS clippings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                folder_id INTEGER,
                item_id INTEGER NOT NULL,
                item_type TEXT DEFAULT 'jurisprudence',
                title TEXT,
                reference_num TEXT,
                content TEXT NOT NULL,
                notes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(folder_id) REFERENCES folders(id)
            )
        `);
    });
    db.close();
}
initUsersDb();

// Helper: Sanitize search input into clean SQLite FTS5 query syntax
const commonTypos = {
    'dismisal': 'dismissal',
    'dismis': 'dismiss',
    'apellate': 'appellate',
    'apelate': 'appellate',
    'certorari': 'certiorari',
    'certirari': 'certiorari',
    'defendent': 'defendant',
    'plantiff': 'plaintiff',
    'jurisdicion': 'jurisdiction',
    'affadavit': 'affidavit',
    'afidavit': 'affidavit'
};

function sanitizeFtsQuery(queryText) {
    if (!queryText) return '';
    
    // 1. Basic Spell Correction
    let processedText = queryText;
    const wordsRaw = processedText.split(/\s+/);
    processedText = wordsRaw.map(w => {
        const lowerW = w.toLowerCase();
        return commonTypos[lowerW] ? commonTypos[lowerW] : w;
    }).join(' ');
    
    // 2. Smart Synonym Engine (Colloquial -> Legal Terms)
    const lowerQuery = processedText.toLowerCase();
    let synonymsToAppend = [];
    
    const colloquialMap = [
        { triggers: ['bounced check', 'bouncing check', 'bad check', 'tumalbog'], terms: ['"B.P. 22"', '"Batas Pambansa Blg. 22"'] },
        { triggers: ['carnapping', 'car napping', 'stolen car'], terms: ['"R.A. 10883"', '"R.A. 6539"'] },
        { triggers: ['estafa', 'swindling', 'fraud', 'scam'], terms: ['"Article 315"', '"Revised Penal Code"'] },
        { triggers: ['libel', 'cyber libel', 'defamation', 'slander'], terms: ['"Cybercrime Prevention Act"', '"Article 353"'] },
        { triggers: ['sexual harassment', 'catcalling', 'bastos'], terms: ['"Safe Spaces Act"', '"R.A. 11313"', '"R.A. 7877"'] },
        { triggers: ['violence against women', 'vawc', 'wife beating', 'abused wife'], terms: ['"R.A. 9262"', '"VAWC"'] },
        { triggers: ['drunk driving', 'dui'], terms: ['"Anti-Drunk and Drugged Driving"', '"R.A. 10586"'] },
        { triggers: ['illegal recruitment', 'human trafficking'], terms: ['"R.A. 8042"', '"R.A. 9208"', '"Migrant Workers Act"'] }
    ];

    colloquialMap.forEach(syn => {
        if (syn.triggers.some(t => lowerQuery.includes(t))) {
            synonymsToAppend.push(...syn.terms);
        }
    });
    
    // 3. Strip special characters except letters, numbers, spaces, and double quotes
    let sanitized = processedText.replace(/[^\w\s\u00C0-\u00FF"]/g, ' ').trim();
    
    // Check for unbalanced double quotes and strip them if they don't form complete pairs
    const quoteCount = (sanitized.match(/"/g) || []).length;
    if (quoteCount % 2 !== 0) {
        sanitized = sanitized.replace(/"/g, '');
    }
    
    const words = sanitized.split(/\s+/).filter(w => w.length > 0);
    
    if (words.length === 0) return '';
    
    // If it's a single phrase in quotes, let it be
    if (sanitized.startsWith('"') && sanitized.endsWith('"') && quoteCount === 2) {
        if (synonymsToAppend.length > 0) {
            return `(${sanitized} OR ${synonymsToAppend.join(' OR ')})`;
        }
        return sanitized;
    }
    
    // Default FTS5 behavior: AND all words together so we do an exact intersection search
    let baseSearch = words.map(word => {
        if (word.startsWith('"') || word.endsWith('"')) {
            return word;
        }
        return `"${word}"`;
    }).join(' AND ');

    // Append the legal synonyms as an OR condition
    if (synonymsToAppend.length > 0) {
        return `(${baseSearch}) OR ${synonymsToAppend.join(' OR ')}`;
    }

    return baseSearch;
}

// Helper: Apply memory-saving pragmas to a SQLite connection
function applyMemoryPragmas(db) {
    db.serialize(() => {
        db.run('PRAGMA cache_size = -8000');   // Limit page cache to 8MB
        db.run('PRAGMA mmap_size = 0');         // Disable memory-mapped I/O
        db.run('PRAGMA temp_store = FILE');     // Store temp tables on disk
        db.run('PRAGMA page_size = 4096');
    });
    return db;
}

// Helper: Open SQLite connection for CASE READING (respects premium/free paywall)
function getDbConnection(premiumRequested = false) {
    // For reading full cases, use the full search DB (db_recent.db covers 1901-2026)
    // The paywall is enforced at the API level, not by DB selection
    let targetPath = DB_SEARCH_PATH;
    
    // Fallback chain if db_recent.db not yet downloaded
    if (!fs.existsSync(targetPath)) {
        if (fs.existsSync(DB_FREE_PATH)) targetPath = DB_FREE_PATH;
        else if (fs.existsSync(DB_PREMIUM_PATH)) targetPath = DB_PREMIUM_PATH;
    }
    
    const db = new sqlite3.Database(targetPath, sqlite3.OPEN_READONLY, (err) => {
        if (err) console.error(`[DB ERROR] Could not open database at ${targetPath}:`, err.message);
    });
    return applyMemoryPragmas(db);
}

// Helper: Open the FULL 1901-2026 search index for ALL users (search only — snippets)
function getSearchDbConnection() {
    let targetPath = DB_SEARCH_PATH;
    
    // Fallback chain if db_recent.db not yet downloaded
    if (!fs.existsSync(targetPath)) {
        if (fs.existsSync(DB_FREE_PATH)) targetPath = DB_FREE_PATH;
        else if (fs.existsSync(DB_PREMIUM_PATH)) targetPath = DB_PREMIUM_PATH;
    }
    
    const db = new sqlite3.Database(targetPath, sqlite3.OPEN_READONLY, (err) => {
        if (err) console.error(`[DB ERROR] Could not open database at ${targetPath}:`, err.message);
    });
    return applyMemoryPragmas(db);
}

function getStatutesDbConnection() {
    const db = new sqlite3.Database(DB_STATUTES_PATH, sqlite3.OPEN_READONLY, (err) => {
        if (err) console.error(`[DB ERROR] Could not open database at ${DB_STATUTES_PATH}:`, err.message);
    });
    return applyMemoryPragmas(db);
}

// Helper: Strip U+FFFD and literal diamond characters from all text fields server-side
const REPLACEMENT_REGEX = new RegExp(`[${String.fromCharCode(65533)}\\u2666\\u25C6]`, 'g');
function sanitizeText(str) {
    if (!str || typeof str !== 'string') return str;
    return str.replace(REPLACEMENT_REGEX, ' ');
}
function sanitizeRow(row) {
    if (!row) return row;
    for (const key of Object.keys(row)) {
        if (typeof row[key] === 'string') {
            row[key] = sanitizeText(row[key]);
        }
    }
    return row;
}

// =======================================================
//                    API ENDPOINTS
// =======================================================

// Auth Middleware: Enforce Single Active Session but allow Guest access
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        req.user = { id: null, username: 'guest', role: 'free' };
        return next();
    }
    const token = authHeader.split(' ')[1];
    
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            req.user = { id: null, username: 'guest', role: 'free' };
            return next();
        }
        
        // Check if this token is the currently active one for the user
        const db = new sqlite3.Database(USERS_DB_PATH, sqlite3.OPEN_READONLY);
        db.get('SELECT current_token_jti, role FROM users WHERE id = ?', [decoded.id], (err, row) => {
            db.close();
            if (err || !row) {
                req.user = { id: null, username: 'guest', role: 'free' };
                return next();
            }
            
            if (row.current_token_jti !== decoded.jti) {
                return res.status(401).json({ error: 'Session invalidated. Logged in from another device.' });
            }
            
            req.user = { id: decoded.id, username: decoded.username, role: row.role };
            next();
        });
    });
}

// Auth: Register
app.post('/api/auth/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Hashing failed' });
        
        db.run('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hash], function(err) {
            db.close();
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Username already exists' });
                }
                return res.status(500).json({ error: 'Database error' });
            }
            res.json({ message: 'User registered successfully', userId: this.lastID });
        });
    });
});

// Auth: Login (Single Active Session Logic)
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
        if (err || !user) {
            db.close();
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        bcrypt.compare(password, user.password_hash, (err, isMatch) => {
            if (err || !isMatch) {
                db.close();
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            // Check if promo access has expired
            if (user.access_expires_at) {
                const today = new Date().toISOString().split('T')[0];
                if (user.access_expires_at < today) {
                    db.close();
                    return res.status(403).json({ 
                        error: `Your promotional access expired on ${user.access_expires_at}. Please subscribe to continue.`,
                        expired: true
                    });
                }
            }

            // Determine effective role (premium unless promo is somehow expired)
            const effectiveRole = user.role;
            
            const jti = Math.random().toString(36).substring(2, 15) + Date.now().toString(36);
            
            const token = jwt.sign(
                { id: user.id, username: user.username, jti: jti },
                JWT_SECRET,
                { expiresIn: '7d' }
            );
            
            db.run('UPDATE users SET current_token_jti = ? WHERE id = ?', [jti, user.id], (err) => {
                db.close();
                if (err) return res.status(500).json({ error: 'Failed to update session' });
                
                res.json({ 
                    message: 'Login successful', 
                    token, 
                    user: { 
                        id: user.id, 
                        username: user.username, 
                        role: effectiveRole,
                        access_expires_at: user.access_expires_at || null
                    } 
                });
            });
        });
    });
});

// Auth: Update Role (Mock Checkout Upgrade)
app.post('/api/auth/upgrade', optionalAuth, (req, res) => {
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run('UPDATE users SET role = ? WHERE id = ?', ['premium', req.user.id], (err) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Upgrade failed' });
        res.json({ message: 'Upgraded to premium' });
    });
});

// =======================================================
//                FOLDERS & BOOKMARKS API
// =======================================================

app.get('/api/folders', optionalAuth, (req, res) => {
    if (!req.user.id) return res.status(401).json({ error: 'Unauthorized' });
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.all('SELECT * FROM folders WHERE user_id = ? ORDER BY created_at ASC', [req.user.id], (err, rows) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ folders: rows || [] });
    });
});

app.post('/api/folders', optionalAuth, (req, res) => {
    if (!req.user.id) return res.status(401).json({ error: 'Unauthorized' });
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Folder name required' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run('INSERT INTO folders (user_id, name) VALUES (?, ?)', [req.user.id, name], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: 'Failed to create folder' });
        res.json({ message: 'Folder created', folder: { id: this.lastID, name: name } });
    });
});

app.get('/api/bookmarks', optionalAuth, (req, res) => {
    if (!req.user.id) return res.status(401).json({ error: 'Unauthorized' });
    const folder_id = req.query.folder_id || null;
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    let query = 'SELECT * FROM bookmarks WHERE user_id = ?';
    let params = [req.user.id];
    
    if (folder_id) {
        query += ' AND folder_id = ?';
        params.push(folder_id);
    } else {
        query += ' AND folder_id IS NULL';
    }
    query += ' ORDER BY created_at DESC';
    
    db.all(query, params, (err, rows) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ bookmarks: rows || [] });
    });
});

app.get('/api/bookmarks/all', optionalAuth, (req, res) => {
    if (!req.user.id) return res.status(401).json({ error: 'Unauthorized' });
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.all('SELECT * FROM bookmarks WHERE user_id = ?', [req.user.id], (err, rows) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json({ bookmarks: rows || [] });
    });
});

app.post('/api/bookmarks', optionalAuth, (req, res) => {
    if (!req.user.id) return res.status(401).json({ error: 'Unauthorized' });
    const { folder_id, folder_name, item_id, item_type, title, reference_num } = req.body;
    if (!item_id) return res.status(400).json({ error: 'Item ID required' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.get('SELECT id FROM bookmarks WHERE user_id = ? AND item_id = ? AND item_type = ?', [req.user.id, String(item_id), item_type || 'jurisprudence'], (err, row) => {
        if (row) {
            db.close();
            // Return existing bookmark id so client can store it
            return res.json({ message: 'Already bookmarked', bookmark_id: row.id });
        }
        
        db.run(`
            INSERT INTO bookmarks (user_id, folder_id, folder_name, item_id, item_type, title, reference_num)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [req.user.id, folder_id || null, folder_name || null, String(item_id), item_type || 'jurisprudence', title, reference_num], function(err) {
            db.close();
            if (err) return res.status(500).json({ error: 'Failed to bookmark' });
            res.json({ message: 'Bookmark added', bookmark_id: this.lastID });
        });
    });
});

app.delete('/api/bookmarks/:id', optionalAuth, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const bookmarkId = req.params.id;
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run(`DELETE FROM bookmarks WHERE id = ? AND user_id = ?`, [bookmarkId, req.user.id], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Bookmark not found or unauthorized' });
        res.json({ message: 'Bookmark deleted' });
    });
});

app.get('/api/clippings', optionalAuth, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { folder_id } = req.query;
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    let query = `SELECT * FROM clippings WHERE user_id = ?`;
    let params = [req.user.id];
    
    if (folder_id) {
        query += ` AND folder_id = ?`;
        params.push(folder_id);
    }
    
    query += ` ORDER BY created_at DESC`;
    
    db.all(query, params, (err, rows) => {
        db.close();
        if (err) return res.status(500).json({ error: err.message });
        res.json({ clippings: rows });
    });
});

app.post('/api/clippings', optionalAuth, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const { folder_id, item_id, item_type, title, reference_num, content, notes } = req.body;
    
    if (!item_id || !content) return res.status(400).json({ error: 'Missing required clipping data' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    const sql = `INSERT INTO clippings (user_id, folder_id, item_id, item_type, title, reference_num, content, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`;
    db.run(sql, [req.user.id, folder_id || null, item_id, item_type || 'jurisprudence', title, reference_num, content, notes || ''], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Clipping saved', clipping_id: this.lastID });
    });
});

app.delete('/api/clippings/:id', optionalAuth, (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    const clippingId = req.params.id;
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run(`DELETE FROM clippings WHERE id = ? AND user_id = ?`, [clippingId, req.user.id], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: 'Clipping not found or unauthorized' });
        res.json({ message: 'Clipping deleted' });
    });
});

// =======================================================
//                SEARCH API
// =======================================================

app.get('/api/search', optionalAuth, (req, res) => {
    const isPremium = req.user.role === 'premium';
    const { q, year, ponente, page, limit, sortBy, type } = req.query;
    const searchType = type || 'jurisprudence';
    
    const pageNum = parseInt(page, 10) || 1;
    const limitNum = parseInt(limit, 10) || 50;
    const offsetNum = (pageNum - 1) * limitNum;
    
    let db;
    try {
        if (searchType === 'statute') {
            db = getStatutesDbConnection();
        } else {
            // ALL users search the full 1901-2026 index — paywall is enforced at read time
            db = getSearchDbConnection();
        }
    } catch (e) {
        return res.status(500).json({ error: 'Databases are not available.' });
    }
    
    let sqlConditions = [];
    let sqlParams = [];
    
    const cleanQuery = sanitizeFtsQuery(q);

    if (searchType === 'statute') {
        // --- STATUTE SEARCH SECTION ---
        if (year) {
            sqlConditions.push(`statutes.year = ?`);
            sqlParams.push(parseInt(year, 10));
        }

        let countSql;
        let querySql;
        
        if (cleanQuery) {
            sqlConditions.push(`statutes_search MATCH ?`);
            sqlParams.push(cleanQuery);
            const whereClause = sqlConditions.length > 0 ? `WHERE ${sqlConditions.join(' AND ')}` : '';
            
            countSql = `
                SELECT COUNT(*) as total 
                FROM statutes
                JOIN statutes_search ON statutes.id = statutes_search.rowid
                ${whereClause};
            `;
            querySql = `
                SELECT 
                    statutes.id, 
                    statutes.law_type,
                    statutes.serial_number,
                    statutes.year,
                    statutes.title,
                    snippet(statutes_search, 2, '<mark>', '</mark>', '...', 12) as result_snippet
                FROM statutes
                JOIN statutes_search ON statutes.id = statutes_search.rowid
                ${whereClause}
                ORDER BY rank
            `;
        } else {
            const whereClause = sqlConditions.length > 0 ? `WHERE ${sqlConditions.join(' AND ')}` : '';
            countSql = `
                SELECT COUNT(*) as total 
                FROM statutes
                ${whereClause};
            `;
            querySql = `
                SELECT 
                    statutes.id, 
                    statutes.law_type,
                    statutes.serial_number,
                    statutes.year,
                    statutes.title,
                    substr(statutes.content, 1, 200) || '...' as result_snippet
                FROM statutes
                ${whereClause}
                ORDER BY statutes.year DESC
            `;
        }

        db.get(countSql, sqlParams, (err, countRow) => {
            if (err) {
                db.close();
                console.error('Statute Count Error:', err.message);
                return res.status(500).json({ error: 'Statute search count failed', details: err.message });
            }
            const total = countRow ? countRow.total : 0;
            const paginatedQuerySql = `${querySql} LIMIT ? OFFSET ?;`;
            const paginatedParams = [...sqlParams, limitNum, offsetNum];

            db.all(paginatedQuerySql, paginatedParams, (err, rows) => {
                db.close();
                if (err) {
                    console.error('Statute Search Error:', err.message);
                    return res.status(500).json({ error: 'Statute search failed', details: err.message });
                }
                res.json({
                    results: rows || [],
                    total: total,
                    page: pageNum,
                    limit: limitNum,
                    totalPages: Math.ceil(total / limitNum)
                });
            });
        });

    } else {
        // --- JURISPRUDENCE SEARCH SECTION ---
        if (year) {
            sqlConditions.push(`cases.decision_date LIKE ?`);
            sqlParams.push(`${year}%`);
        }
        
        if (ponente) {
            sqlConditions.push(`cases.ponente LIKE ?`);
            sqlParams.push(`%${ponente}%`);
        }
        
        let countSql;
        let querySql;
        let orderClause = '';
        
        if (cleanQuery) {
            sqlConditions.push(`cases_search MATCH ?`);
            sqlParams.push(cleanQuery);
            
            const whereClause = sqlConditions.length > 0 ? `WHERE ${sqlConditions.join(' AND ')}` : '';
            
            countSql = `
                SELECT COUNT(*) as total 
                FROM cases
                JOIN cases_search ON cases.id = cases_search.rowid
                ${whereClause};
            `;
            
            if (sortBy === 'date_desc') {
                orderClause = 'ORDER BY cases.decision_date DESC';
            } else if (sortBy === 'date_asc') {
                orderClause = 'ORDER BY cases.decision_date ASC';
            } else if (sortBy === 'title_asc') {
                orderClause = 'ORDER BY cases.title ASC';
            } else {
                orderClause = 'ORDER BY rank';
            }
            
            querySql = `
                SELECT 
                    cases.id, 
                    cases.gr_number, 
                    cases.title, 
                    cases.decision_date, 
                    cases.ponente,
                    snippet(cases_search, 4, '<mark>', '</mark>', '...', 12) as result_snippet,
                    CASE WHEN cp.id IS NOT NULL THEN 1 ELSE 0 END as is_overruled
                FROM cases
                JOIN cases_search ON cases.id = cases_search.rowid
                LEFT JOIN case_precedents cp ON cases.gr_number = cp.case_gr
                ${whereClause}
                ${orderClause}
            `;
        } else {
            const whereClause = sqlConditions.length > 0 ? `WHERE ${sqlConditions.join(' AND ')}` : '';
            
            countSql = `
                SELECT COUNT(*) as total 
                FROM cases
                ${whereClause};
            `;
            
            if (sortBy === 'date_asc') {
                orderClause = 'ORDER BY cases.decision_date ASC';
            } else if (sortBy === 'title_asc') {
                orderClause = 'ORDER BY cases.title ASC';
            } else {
                orderClause = 'ORDER BY cases.decision_date DESC';
            }
            
            querySql = `
                SELECT 
                    cases.id, 
                    cases.gr_number, 
                    cases.title, 
                    cases.decision_date, 
                    cases.ponente,
                    substr(cases.full_text, 1, 200) || '...' as result_snippet,
                    CASE WHEN cp.id IS NOT NULL THEN 1 ELSE 0 END as is_overruled
                FROM cases
                LEFT JOIN case_precedents cp ON cases.gr_number = cp.case_gr
                ${whereClause}
                ${orderClause}
            `;
        }
        
        db.get(countSql, sqlParams, (err, countRow) => {
            if (err) {
                db.close();
                console.error('SQL Count Error:', err.message);
                return res.status(500).json({ error: 'Search count failed', details: err.message });
            }
            
            const total = countRow ? countRow.total : 0;
            const paginatedQuerySql = `${querySql} LIMIT ? OFFSET ?;`;
            const paginatedParams = [...sqlParams, limitNum, offsetNum];
            
            db.all(paginatedQuerySql, paginatedParams, (err, rows) => {
                db.close();
                if (err) {
                    console.error('SQL Search Error:', err.message);
                    return res.status(500).json({ error: 'Search failed', details: err.message });
                }
                const cleanRows = (rows || []).map(r => sanitizeRow(r));
                res.json({
                    results: cleanRows,
                    total: total,
                    page: pageNum,
                    limit: limitNum,
                    totalPages: Math.ceil(total / limitNum)
                });
            });
        });
    }
});

// Helper to extract digit portion of GR for citation checks
function cleanGrNumberToDigits(grStr) {
    if (!grStr) return '';
    let cleaned = grStr.replace(/^(?:G\.?R\.?\s*(?:No\.?\s*)?|GR\s+)/i, '').trim();
    const match = cleaned.match(/^([L-\d]+)/i);
    if (match) {
        return match[1].replace(/[^\d]/g, '').trim();
    }
    return '';
}

// Fetch Single Case Full-Text
app.get('/api/case/:id', optionalAuth, (req, res) => {
    const { id } = req.params;
    const isPremium = req.user.role === 'premium';
    
    const db = getDbConnection(isPremium);
    
    db.get('SELECT * FROM cases WHERE id = ?', [id], (err, row) => {
        if (err) {
            db.close();
            return res.status(500).json({ error: 'Fetch failed', details: err.message });
        }
        if (!row) {
            db.close();
            return res.status(404).json({ error: 'Case not found' });
        }
        
        // Server-side Premium Verification
        if (!isPremium) {
            const decisionDate = row.decision_date;
            if (decisionDate && decisionDate !== 'Unspecified') {
                const yearMatch = decisionDate.match(/^(\d{4})/);
                if (yearMatch) {
                    const caseYear = parseInt(yearMatch[1], 10);
                    const freeYears = [2025, 2026];
                    if (!freeYears.includes(caseYear)) {
                        db.close();
                        return res.status(403).json({ error: 'Decision Locked (Premium Only)', year: caseYear });
                    }
                }
            }
        }
        
        const cleanGr = cleanGrNumberToDigits(row.gr_number);
        
        db.all(`
            SELECT DISTINCT cases.id, cases.gr_number, cases.title, cases.decision_date 
            FROM cases
            JOIN case_citations ON cases.id = case_citations.source_case_id
            WHERE case_citations.target_case_gr = ?
            ORDER BY cases.decision_date DESC
            LIMIT 10
        `, [cleanGr], (err, citingRows) => {
            if (err) {
                db.close();
                return res.status(500).json({ error: 'Failed retrieving citing relations' });
            }
            
            db.get(`SELECT * FROM case_precedents WHERE case_gr = ?`, [cleanGr], (err, precedentRow) => {
                db.close();
                
                const cleanRow = sanitizeRow(row);
                res.json({
                    case: cleanRow,
                    citedByCount: citingRows ? citingRows.length : 0,
                    citedByCases: citingRows || [],
                    overruledInfo: precedentRow ? { overruled_by_gr: precedentRow.overruled_by_gr, warning_msg: precedentRow.warning_msg } : null
                });
            });
        });
    });
});

// Fetch Statute by ID
app.get('/api/statute/:id', optionalAuth, (req, res) => {
    const { id } = req.params;
    const db = getStatutesDbConnection();

    db.get('SELECT * FROM statutes WHERE id = ?', [id], (err, row) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Fetch statute failed' });
        if (!row) return res.status(404).json({ error: 'Statute not found' });

        res.json({ statute: sanitizeRow(row) });
    });
});

// Fetch Statute by Type and Serial Number Reference
app.get('/api/statutes/:type/:ref', optionalAuth, (req, res) => {
    const { type, ref } = req.params;
    const db = getStatutesDbConnection();

    db.get('SELECT * FROM statutes WHERE law_type = ? AND serial_number = ?', [type.toUpperCase(), ref], (err, row) => {
        db.close();
        if (err) return res.status(500).json({ error: 'Fetch statute failed' });
        if (!row) return res.status(404).json({ error: 'Statute not found' });

        res.json({ statute: sanitizeRow(row) });
    });
});

// Fetch Case by G.R. Number (for hyperlink citation clicks)
app.get('/api/case/gr/:gr', optionalAuth, (req, res) => {
    const { gr } = req.params;
    const isPremium = req.user.role === 'premium';
    const db = getDbConnection(isPremium);

    const cleanGr = gr.replace(/[^\d]/g, '').trim();

    db.get('SELECT * FROM cases WHERE gr_number LIKE ?', [`%${cleanGr}%`], (err, row) => {
        if (err) {
            db.close();
            return res.status(500).json({ error: 'Fetch case failed' });
        }
        if (!row) {
            db.close();
            return res.status(404).json({ error: 'Case not found for citation' });
        }

        if (!isPremium) {
            const decisionDate = row.decision_date;
            if (decisionDate && decisionDate !== 'Unspecified') {
                const yearMatch = decisionDate.match(/^(\d{4})/);
                if (yearMatch) {
                    const caseYear = parseInt(yearMatch[1], 10);
                    if (![2025, 2026].includes(caseYear)) {
                        db.close();
                        return res.status(403).json({ error: 'Decision Locked (Premium Only)', year: caseYear });
                    }
                }
            }
        }

        const cleanGrDigit = cleanGrNumberToDigits(row.gr_number);

        db.all(`
            SELECT DISTINCT cases.id, cases.gr_number, cases.title, cases.decision_date 
            FROM cases
            JOIN case_citations ON cases.id = case_citations.source_case_id
            WHERE case_citations.target_case_gr = ?
            ORDER BY cases.decision_date DESC
            LIMIT 10
        `, [cleanGrDigit], (err, citingRows) => {
            if (err) {
                db.close();
                return res.status(500).json({ error: 'Failed retrieving citing relations' });
            }
            
            db.get(`SELECT * FROM case_precedents WHERE case_gr = ?`, [cleanGrDigit], (err, precedentRow) => {
                db.close();
                
                res.json({
                    case: sanitizeRow(row),
                    citedByCount: citingRows ? citingRows.length : 0,
                    citedByCases: citingRows || [],
                    overruledInfo: precedentRow ? { overruled_by_gr: precedentRow.overruled_by_gr, warning_msg: precedentRow.warning_msg } : null
                });
            });
        });
    });
});

// Dynamic Sidebar Filters Loader
app.get('/api/filters', optionalAuth, (req, res) => {
    const isPremium = req.user.role === 'premium';
    
    const db = getDbConnection(isPremium);
    
    db.all('SELECT DISTINCT ponente FROM cases ORDER BY ponente ASC', [], (err, ponenteRows) => {
        if (err) {
            db.close();
            return res.status(500).json({ error: 'Failed loading filters', details: err.message });
        }
        
        db.all('SELECT DISTINCT SUBSTR(decision_date, 1, 4) as year FROM cases ORDER BY year DESC', [], (err, yearRows) => {
            db.close();
            if (err) {
                return res.status(500).json({ error: 'Failed loading filters', details: err.message });
            }
            
            const ponentes = ponenteRows.map(r => r.ponente).filter(p => p && p !== 'Unspecified');
            const years = yearRows.map(r => r.year).filter(y => y && y !== 'Unsp');
            
            res.json({ ponentes, years });
        });
    });
});

// Admin: Get All Users
app.get('/api/admin/users', async (req, res) => {
    try {
        // Fetch users from Cloudflare KV live database
        const kvRes = await fetch(`${CLOUDFLARE_WORKER_URL}/api/admin/kv-users`, {
            headers: { 'Authorization': `Bearer ${CLOUDFLARE_ADMIN_SECRET}` }
        });
        
        if (!kvRes.ok) throw new Error('Failed to fetch from Cloudflare KV');
        
        const data = await kvRes.json();
        const kvUsers = data.users || [];
        
        const today = new Date().toISOString().split('T')[0];
        
        // Format to match admin UI
        const enrichedRows = kvUsers.map((u, i) => {
            const isExpired = u.access_expires_at && u.access_expires_at < today;
            const isPromo   = !!u.access_expires_at;
            
            return {
                id: i + 1, // Mock ID for sorting display
                email: u.username,
                plan: isPromo ? `Promo (expires ${u.access_expires_at})` : (u.role === 'premium' ? 'Lifetime Pass' : 'Free Plan'),
                access: (u.role === 'premium' && !isExpired) ? 'Active Premium' : (isExpired ? 'Expired Promo' : (u.role === 'free' ? 'Guest Free' : u.role)),
                amount: isPromo ? 0 : (u.role === 'premium' ? 1499 : 0),
                date: u.created_at ? u.created_at.split('T')[0] : '2026-05-20',
                expires: u.access_expires_at || null
            };
        });
        
        // Append local SQLite users as well just in case
        const db = new sqlite3.Database(USERS_DB_PATH, sqlite3.OPEN_READONLY);
        db.all('SELECT id, username, role, access_expires_at FROM users', [], (err, rows) => {
            db.close();
            if (!err) {
                const localUsernames = new Set(enrichedRows.map(r => r.email));
                rows.forEach(r => {
                    if (!localUsernames.has(r.username)) {
                        const isExpired = r.access_expires_at && r.access_expires_at < today;
                        const isPromo   = !!r.access_expires_at;
                        enrichedRows.push({
                            id: 90000 + r.id, // Offset ID so it doesn't collide
                            email: r.username,
                            plan: isPromo ? `Promo [Local] (expires ${r.access_expires_at})` : (r.role === 'premium' ? 'Local Lifetime' : 'Local Free'),
                            access: (r.role === 'premium' && !isExpired) ? 'Active Premium' : (isExpired ? 'Expired Promo' : 'Guest Free'),
                            amount: 0,
                            date: '2026-05-20',
                            expires: r.access_expires_at || null
                        });
                    }
                });
            }
            res.json({ users: enrichedRows });
        });
    } catch (err) {
        console.error('KV fetch error:', err);
        return res.status(500).json({ error: 'Failed to fetch users from Cloudflare KV', details: err.message });
    }
});

// Admin: Create Promo Account
app.post('/api/admin/users/create', async (req, res) => {
    const { username, password, role, access_expires_at } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
    
    // First, push to Cloudflare KV
    try {
        const kvRes = await fetch(`${CLOUDFLARE_WORKER_URL}/api/admin/kv-users`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${CLOUDFLARE_ADMIN_SECRET}`
            },
            body: JSON.stringify({
                accounts: [{ username, password, role, access_expires_at }]
            })
        });
        
        if (!kvRes.ok) {
            const errBody = await kvRes.text();
            throw new Error(`KV Sync Failed: ${errBody}`);
        }
    } catch (err) {
        console.error('Cloudflare KV Sync error:', err);
        return res.status(500).json({ error: 'Failed to sync account to live web database.', details: err.message });
    }

    // Then save locally
    const db = new sqlite3.Database(USERS_DB_PATH);
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Hashing failed' });
        
        db.run(
            'INSERT INTO users (username, password_hash, role, access_expires_at) VALUES (?, ?, ?, ?)',
            [username, hash, role || 'premium', access_expires_at || null],
            function(err) {
                db.close();
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(400).json({ error: 'Username already exists locally, but was synced to Cloudflare.' });
                    }
                    return res.status(500).json({ error: 'Local database error, but synced to Cloudflare.' });
                }
                res.json({ message: 'Promo account created & synced successfully', userId: this.lastID });
            }
        );
    });
});

// Admin: Bulk Create Promo Accounts
app.post('/api/admin/users/bulk-create', async (req, res) => {
    const { seed, count, password, access_expires_at } = req.body;
    
    if (!seed || !count || !password) {
        return res.status(400).json({ error: 'Seed, count, and password required' });
    }
    
    const qty = parseInt(count, 10);
    if (isNaN(qty) || qty < 1 || qty > 1000) {
        return res.status(400).json({ error: 'Count must be between 1 and 1000' });
    }

    // Generate accounts list
    const accountsCreated = [];
    for (let i = 1; i <= qty; i++) {
        const suffix = i.toString().padStart(3, '0');
        accountsCreated.push({
            username: `${seed}${suffix}`,
            password,
            role: 'premium',
            access_expires_at: access_expires_at || null
        });
    }

    // First, push bulk to Cloudflare KV
    try {
        const kvRes = await fetch(`${CLOUDFLARE_WORKER_URL}/api/admin/kv-users`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${CLOUDFLARE_ADMIN_SECRET}`
            },
            body: JSON.stringify({ accounts: accountsCreated })
        });
        
        if (!kvRes.ok) {
            const errBody = await kvRes.text();
            throw new Error(`KV Bulk Sync Failed: ${errBody}`);
        }
    } catch (err) {
        console.error('Cloudflare KV Bulk Sync error:', err);
        return res.status(500).json({ error: 'Failed to sync bulk accounts to live web.', details: err.message });
    }
    
    // Then save locally
    bcrypt.hash(password, 10, (err, hash) => {
        if (err) return res.status(500).json({ error: 'Hashing failed' });
        
        const db = new sqlite3.Database(USERS_DB_PATH);
        
        db.serialize(() => {
            db.run('BEGIN TRANSACTION');
            
            const stmt = db.prepare(
                'INSERT INTO users (username, password_hash, role, access_expires_at) VALUES (?, ?, ?, ?)'
            );
            let errorOccurred = false;
            
            for (const acc of accountsCreated) {
                stmt.run([acc.username, hash, acc.role, acc.access_expires_at], function(err) {
                    if (err) errorOccurred = true;
                });
            }
            
            stmt.finalize();
            
            db.run('COMMIT', (err) => {
                db.close();
                if (err || errorOccurred) {
                    return res.json({ 
                        warning: 'Synced to live web, but local SQLite bulk creation had some errors (e.g. duplicate username locally).',
                        accounts: accountsCreated 
                    });
                }
                
                res.json({ 
                    message: `Successfully generated and synced ${qty} premium promo accounts.`,
                    accounts: accountsCreated
                });
            });
        });
    });
});

// Admin: Update User Role
app.post('/api/admin/users/update-role', (req, res) => {
    const { username, role } = req.body;
    if (!username || !role) return res.status(400).json({ error: 'Username and role required' });
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run('UPDATE users SET role = ? WHERE username = ?', [role, username], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: 'Update failed' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: `User ${username} role updated to ${role}` });
    });
});

// Admin: Delete User Account
app.delete('/api/admin/users/:username', (req, res) => {
    const { username } = req.params;
    
    const db = new sqlite3.Database(USERS_DB_PATH);
    db.run('DELETE FROM users WHERE username = ?', [username], function(err) {
        db.close();
        if (err) return res.status(500).json({ error: 'Failed to delete user' });
        if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
        res.json({ message: `User ${username} has been permanently deleted.` });
    });
});

// =======================================================
//                  SERVER BOOTSTRAP
// =======================================================
app.listen(PORT, '0.0.0.0', () => {
    console.log('========================================================');
    console.log(`📡 SCJurisPH API Backend active on port: ${PORT}`);
    console.log(`📂 Data directory: ${DATA_DIR}`);
    console.log(`📊 Databases available:`);
    console.log(`   Free DB:     ${fs.existsSync(DB_FREE_PATH) ? '✅' : '❌'} ${DB_FREE_PATH}`);
    console.log(`   Premium DB:  ${fs.existsSync(DB_PREMIUM_PATH) ? '✅' : '❌'} ${DB_PREMIUM_PATH}`);
    console.log(`   Statutes DB: ${fs.existsSync(DB_STATUTES_PATH) ? '✅' : '❌'} ${DB_STATUTES_PATH}`);
    console.log(`   Users DB:    ${fs.existsSync(USERS_DB_PATH) ? '✅' : '❌'} ${USERS_DB_PATH}`);
    console.log('========================================================');
});
