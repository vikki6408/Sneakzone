const express = require('express');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const { body, validationResult } = require('express-validator');
const path = require('path');

// Importations des modules
const { initDatabase, dbAll, dbGet, dbRun } = require('./database');
const AdminFunctions = require('./admin');

const app = express();

// ==================== MIDDLEWARE DE SÉCURITÉ ====================
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
            scriptSrcAttr: ["'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'", "https:"],
        }
    },
    crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: {
        success: false,
        message: 'Trop de tentatives de connexion. Réessayez dans 15 minutes.'
    },
    skipSuccessfulRequests: true,
    keyGenerator: (req) => {
        // Vérifier si req.body existe et a un email
        if (req.body && typeof req.body === 'object' && req.body.email) {
            return req.ip + '-' + req.body.email;
        }

        return req.ip + '-unknown';
    }
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { success: false, message: 'Trop de requêtes. Réessayez plus tard.' }
});

// Appliquer le rate limiting uniquement aux routes spécifiques
app.use('/api/auth/login', authLimiter);
app.use('/api/auth/register', authLimiter);
app.use('/api', apiLimiter);

// Session
app.use(session({
    secret: process.env.SESSION_SECRET || 'sneakzone_secret_key_2024_very_long_and_secure',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 30 * 60 * 1000,
        sameSite: 'lax'
    }
}));

// CSRF Protection
const csrfProtection = csrf({ cookie: false });
app.get('/api/csrf-token', csrfProtection, (req, res) => {
    res.json({ success: true, csrfToken: req.csrfToken() });
});
app.use('/api', (req, res, next) => {
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
    csrfProtection(req, res, next);
});

// Servir les fichiers statiques
app.use(express.static(path.join(__dirname, 'public')));

// ==================== MIDDLEWARE PERSONNALISÉ ====================

// Authentification
const authenticateToken = async (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ success: false, message: 'Non authentifié' });
    }

    try {
        const user = await dbGet(
            'SELECT id, email, first_name, last_name, role, is_active FROM users WHERE id = ?',
            [req.session.userId]
        );

        if (!user || !user.is_active) {
            return res.status(401).json({ success: false, message: 'Utilisateur non trouvé ou désactivé' });
        }

        req.user = user;
        next();
    } catch (error) {
        console.error('Erreur authentification:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
};

// Vérification admin
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ success: false, message: 'Accès administrateur requis' });
    }
    next();
};

// Validation
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            message: 'Données invalides',
            errors: errors.array()
        });
    }
    next();
};

// ==================== ROUTES PUBLIQUES ====================

// Produits produits
app.get('/api/products', async (req, res) => {
    try {
        const products = await dbAll('SELECT * FROM products');
        res.json({ success: true, products });
    } catch (error) {
        console.error('Erreur produits:', error);
        res.status(500).json({ success: false, message: 'Erreur serveur' });
    }
});

// ==================== ROUTES AUTHENTIFICATION ====================

// Inscription
app.post('/api/auth/register', [
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 }),
    body('firstName').isLength({ min: 2, max: 50 }),
    body('lastName').isLength({ min: 2, max: 50 })
], handleValidationErrors, async (req, res) => {
    try {
        const { email, password, firstName, lastName } = req.body;

        // Vérifier si l'email existe
        const existingUser = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (existingUser) {
            return res.status(400).json({ success: false, message: 'Un compte avec cet email existe déjà' });
        }

        // Hasher le mot de passe
        const hashedPassword = await bcrypt.hash(password, 12);

        // Créer l'utilisateur
        const result = await dbRun(
            'INSERT INTO users (email, password, first_name, last_name) VALUES (?, ?, ?, ?)',
            [email, hashedPassword, firstName, lastName]
        );

        // Connexion automatique
        req.session.userId = result.id;

        // Récupérer l'utilisateur créé
        const newUser = await dbGet(
            'SELECT id, email, first_name, last_name, role FROM users WHERE id = ?',
            [result.id]
        );

        res.json({
            success: true,
            message: 'Compte créé avec succès',
            user: {
                id: newUser.id,
                email: newUser.email,
                firstName: newUser.first_name,
                lastName: newUser.last_name,
                role: newUser.role
            }
        });

    } catch (error) {
        console.error('Erreur inscription:', error);
        res.status(500).json({ success: false, message: 'Erreur création compte' });
    }
});

// Connexion
app.post('/api/auth/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], handleValidationErrors, async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await dbGet(
            'SELECT id, email, password, first_name, last_name, role, is_active FROM users WHERE email = ?',
            [email]
        );

        if (!user) {
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        if (!user.is_active) {
            return res.status(401).json({ success: false, message: 'Compte désactivé' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Email ou mot de passe incorrect' });
        }

        req.session.userId = user.id;

        res.json({
            success: true,
            message: 'Connexion réussie',
            user: {
                id: user.id,
                email: user.email,
                firstName: user.first_name,
                lastName: user.last_name,
                role: user.role
            }
        });

    } catch (error) {
        console.error('Erreur connexion:', error);
        res.status(500).json({ success: false, message: 'Erreur connexion' });
    }
});

// Vérification session
app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({ success: true, user: req.user });
});

// Déconnexion
app.post('/api/auth/logout', (req, res) => {
    // CORRECTION : Nettoyer complètement la session
    const sessionId = req.sessionID;

    req.session.destroy((err) => {
        if (err) {
            console.error('Erreur destruction session:', err);
            return res.status(500).json({ success: false, message: 'Erreur déconnexion' });
        }

        // CORRECTION : Nettoyer aussi le cookie côté client
        res.clearCookie('connect.sid');

        res.json({
            success: true,
            message: 'Déconnexion réussie'
        });
    });
});

// ==================== ROUTES UTILISATEUR ====================

// Favoris
app.get('/api/users/favorites', authenticateToken, async (req, res) => {
    try {
        const favorites = await dbAll(`
            SELECT p.*, f.created_at as favorited_at 
            FROM favorites f 
            JOIN products p ON f.product_id = p.id 
            WHERE f.user_id = ?
            ORDER BY f.created_at DESC
        `, [req.user.id]);

        res.json({ success: true, favorites });
    } catch (error) {
        console.error('Erreur favoris:', error);
        res.status(500).json({ success: false, message: 'Erreur récupération favoris' });
    }
});

// Favoris
app.post('/api/users/favorites/:productName', authenticateToken, async (req, res) => {
    try {
        const { productName } = req.params;
        const decodedProductName = decodeURIComponent(productName);

        const product = await dbGet('SELECT id FROM products WHERE name = ?', [decodedProductName]);
        if (!product) {
            return res.status(404).json({ success: false, message: 'Produit non trouvé' });
        }

        const existingFavorite = await dbGet(
            'SELECT id FROM favorites WHERE user_id = ? AND product_id = ?',
            [req.user.id, product.id]
        );

        if (existingFavorite) {
            await dbRun('DELETE FROM favorites WHERE id = ?', [existingFavorite.id]);
            res.json({ success: true, message: 'Produit retiré des favoris', isFavorite: false });
        } else {
            await dbRun('INSERT INTO favorites (user_id, product_id) VALUES (?, ?)', [req.user.id, product.id]);
            res.json({ success: true, message: 'Produit ajouté aux favoris', isFavorite: true });
        }
    } catch (error) {
        console.error('Erreur toggle favoris:', error);
        res.status(500).json({ success: false, message: 'Erreur gestion favoris' });
    }
});

// Panier
app.get('/api/users/cart', authenticateToken, async (req, res) => {
    try {
        const cartItems = await dbAll(`
            SELECT p.*, c.quantity 
            FROM cart_items c 
            JOIN products p ON c.product_id = p.id 
            WHERE c.user_id = ?
        `, [req.user.id]);

        res.json({ success: true, cartItems });
    } catch (error) {
        console.error('Erreur panier:', error);
        res.status(500).json({ success: false, message: 'Erreur récupération panier' });
    }
});

// Panier
app.post('/api/users/cart/:productName', authenticateToken, async (req, res) => {
    try {
        const { productName } = req.params;
        const decodedProductName = decodeURIComponent(productName);

        const product = await dbGet('SELECT id FROM products WHERE name = ?', [decodedProductName]);
        if (!product) {
            return res.status(404).json({ success: false, message: 'Produit non trouvé' });
        }

        const existingItem = await dbGet(
            'SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?',
            [req.user.id, product.id]
        );

        if (existingItem) {
            await dbRun('UPDATE cart_items SET quantity = quantity + 1 WHERE id = ?', [existingItem.id]);
        } else {
            await dbRun('INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, 1)', [req.user.id, product.id]);
        }

        res.json({ success: true, message: 'Produit ajouté au panier' });
    } catch (error) {
        console.error('Erreur ajout panier:', error);
        res.status(500).json({ success: false, message: 'Erreur ajout panier' });
    }
});


// Suppression panier
app.delete('/api/users/cart/:productName', authenticateToken, async (req, res) => {
    try {
        const { productName } = req.params;
        const decodedProductName = decodeURIComponent(productName);

        const product = await dbGet('SELECT id FROM products WHERE name = ?', [decodedProductName]);
        if (!product) {
            return res.status(404).json({ success: false, message: 'Produit non trouvé' });
        }

        await dbRun('DELETE FROM cart_items WHERE user_id = ? AND product_id = ?', [req.user.id, product.id]);

        res.json({ success: true, message: 'Produit retiré du panier' });
    } catch (error) {
        console.error('Erreur suppression panier:', error);
        res.status(500).json({ success: false, message: 'Erreur suppression panier' });
    }
});

// ==================== ROUTES ADMIN ====================

// Gestion utilisateurs
app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
    const result = await AdminFunctions.getUsers();
    res.json(result);
});

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
    const result = await AdminFunctions.getStats();
    res.json(result);
});

app.put('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    const { userId } = req.params;

    if (parseInt(userId) === req.user.id) {
        return res.status(400).json({ success: false, message: 'Impossible de modifier son propre compte' });
    }

    const result = await AdminFunctions.updateUser(userId, req.body);
    res.json(result);
});

app.delete('/api/admin/users/:userId', authenticateToken, requireAdmin, async (req, res) => {
    const { userId } = req.params;

    if (parseInt(userId) === req.user.id) {
        return res.status(400).json({ success: false, message: 'Impossible de supprimer son propre compte' });
    }

    const result = await AdminFunctions.deleteUser(userId);
    res.json(result);
});

// Gestion produits admin
app.get('/api/admin/products', authenticateToken, requireAdmin, async (req, res) => {
    const result = await AdminFunctions.getAllProducts();
    res.json(result);
});

app.post('/api/admin/products', authenticateToken, requireAdmin, async (req, res) => {
    const result = await AdminFunctions.addProduct(req.body);
    res.json(result);
});

// ==================== GESTION D'ERREURS ====================

app.use((err, req, res, next) => {
    if (err.code === 'EBADCSRFTOKEN') {
        return res.status(403).json({ success: false, message: 'Token CSRF invalide' });
    }
    next(err);
});

// Route SPA
app.use((req, res) => {
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({
            success: false,
            message: 'Route API non trouvée'
        });
    }
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== DÉMARRAGE SERVEUR ====================

const startServer = async () => {
    try {
        await initDatabase();

        const PORT = process.env.PORT || 3000;

        // Stocker la référence du serveur
        const server = app.listen(PORT, () => {
            console.log(`Serveur SneakZone démarré sur http://localhost:${PORT}`);
            console.log('\nAppuyez sur Ctrl+C pour arrêter le serveur\n');
        });

        // Gestion des erreurs de port
        server.on('error', (error) => {
            if (error.code === 'EADDRINUSE') {
                console.error(`Le port ${PORT} est déjà utilisé!`);
                console.log('💡 Essayez un autre port: PORT=3001 npm start');
            } else {
                console.error('Erreur serveur:', error);
            }
            process.exit(1);
        });

    } catch (error) {
        console.error('Erreur démarrage serveur:', error);
        process.exit(1);
    }
};

// Démarrer le serveur
startServer();