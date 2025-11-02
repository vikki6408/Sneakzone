const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.join(__dirname, 'sneakzone.db');
const db = new sqlite3.Database(dbPath);

// Initialisation de la base de données
const initDatabase = async () => {
    return new Promise((resolve, reject) => {

        const initSQL = `
            -- Table utilisateurs
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                first_name VARCHAR(100) NOT NULL,
                last_name VARCHAR(100) NOT NULL,
                role VARCHAR(20) DEFAULT 'user' CHECK(role IN ('user', 'admin')),
                is_active BOOLEAN DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Table produits
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(255) NOT NULL,
                brand VARCHAR(100) NOT NULL,
                description TEXT,
                price DECIMAL(10,2) NOT NULL,
                image_emoji VARCHAR(10),
                sizes TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );

            -- Table favoris
            CREATE TABLE IF NOT EXISTS favorites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                UNIQUE(user_id, product_id)
            );

            -- Table panier
            CREATE TABLE IF NOT EXISTS cart_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                product_id INTEGER NOT NULL,
                quantity INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE,
                UNIQUE(user_id, product_id)
            );
        `;

        db.exec(initSQL, async (err) => {
            if (err) {
                console.error('Erreur création tables:', err);
                reject(err);
                return;
            }

            try {
                // Créer l'admin par défaut
                const adminHash = await bcrypt.hash('#Adm1nSneakZone97!', 12);
                db.run(
                    `INSERT OR IGNORE INTO users (email, password, first_name, last_name, role) 
                     VALUES (?, ?, ?, ?, ?)`,
                    ['admin@sneakzone.com', adminHash, 'Admin', 'SneakZone', 'admin'],
                    function(err) {
                        if (err && !err.message.includes('UNIQUE')) {
                            console.error('Erreur création admin:', err);
                        }
                    }
                );

                // Insérer les produits
                const products = [
                    ['Air Jordan 1 Retro High', 'NIKE', 'Chicago - Rouge/Blanc/Noir', 179.00, '👟', '38-46'],
                    ['Yeezy Boost 350 V2', 'ADIDAS', 'Zebra - Blanc/Noir', 249.00, '🏃', '36-45'],
                    ['Air Max 90', 'NIKE', 'Triple White', 129.00, '⚡', '37-47']
                ];

                products.forEach(product => {
                    db.run(
                        `INSERT OR IGNORE INTO products (name, brand, description, price, image_emoji, sizes) 
                         VALUES (?, ?, ?, ?, ?, ?)`,
                        product,
                        function(err) {
                            if (err && !err.message.includes('UNIQUE')) {
                                console.error('Erreur produit:', err);
                            }
                        }
                    );
                });
                resolve();
            } catch (error) {
                reject(error);
            }
        });
    });
};

// Fonctions utilitaires base de données
const dbAll = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                console.error('Erreur dbAll:', err.message);
                reject(err);
            } else {
                resolve(rows || []);
            }
        });
    });
};

const dbGet = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                console.error('Erreur dbGet:', err.message);
                reject(err);
            } else {
                resolve(row || null);
            }
        });
    });
};

const dbRun = (sql, params = []) => {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function(err) {
            if (err) {
                console.error('Erreur dbRun:', err.message);
                reject(err);
            } else {
                resolve({ id: this.lastID, changes: this.changes });
            }
        });
    });
};

module.exports = {
    db,
    dbAll,
    dbGet,
    dbRun,
    initDatabase
};