const { dbAll, dbGet, dbRun } = require('./database');

class AdminFunctions {
    // Récupérer tous les utilisateurs
    static async getUsers() {
        try {
            const users = await dbAll(`
                SELECT id, email, first_name, last_name, role, is_active, created_at 
                FROM users 
                ORDER BY created_at DESC
            `);
            return { success: true, users };
        } catch (error) {
            console.error('Erreur getUsers:', error);
            return { success: false, message: 'Erreur serveur', users: [] };
        }
    }

    // Récupérer les statistiques
    static async getStats() {
        try {
            const totalUsers = await dbGet('SELECT COUNT(*) as count FROM users');
            const totalAdmins = await dbGet('SELECT COUNT(*) as count FROM users WHERE role = "admin"');
            const activeUsers = await dbGet('SELECT COUNT(*) as count FROM users WHERE is_active = 1');
            const totalProducts = await dbGet('SELECT COUNT(*) as count FROM products');

            return {
                success: true,
                stats: {
                    totalUsers: totalUsers.count,
                    totalAdmins: totalAdmins.count,
                    activeUsers: activeUsers.count,
                    totalProducts: totalProducts.count,
                    totalRegularUsers: totalUsers.count - totalAdmins.count
                }
            };
        } catch (error) {
            console.error('Erreur getStats:', error);
            return { success: false, message: 'Erreur statistiques' };
        }
    }

    // Modifier un utilisateur
    static async updateUser(userId, updates) {
        try {
            const validUpdates = {};
            if (updates.role && ['user', 'admin'].includes(updates.role)) {
                validUpdates.role = updates.role;
            }
            if (typeof updates.is_active === 'boolean') {
                validUpdates.is_active = updates.is_active;
            }

            if (Object.keys(validUpdates).length === 0) {
                return { success: false, message: 'Aucune modification valide' };
            }

            const setClause = Object.keys(validUpdates).map(key => `${key} = ?`).join(', ');
            const values = Object.values(validUpdates);
            values.push(userId);

            await dbRun(`UPDATE users SET ${setClause} WHERE id = ?`, values);

            return { success: true, message: 'Utilisateur modifié avec succès' };
        } catch (error) {
            console.error('Erreur updateUser:', error);
            return { success: false, message: 'Erreur modification' };
        }
    }

    // Supprimer un utilisateur
    static async deleteUser(userId) {
        try {
            await dbRun('DELETE FROM users WHERE id = ?', [userId]);
            return { success: true, message: 'Utilisateur supprimé avec succès' };
        } catch (error) {
            console.error('Erreur deleteUser:', error);
            return { success: false, message: 'Erreur suppression' };
        }
    }

    // Ajouter un produit
    static async addProduct(productData) {
        try {
            const { name, brand, description, price, image_emoji, sizes } = productData;

            await dbRun(
                `INSERT INTO products (name, brand, description, price, image_emoji, sizes) 
                 VALUES (?, ?, ?, ?, ?, ?)`,
                [name, brand, description, price, image_emoji, sizes]
            );

            return { success: true, message: 'Produit ajouté avec succès' };
        } catch (error) {
            console.error('Erreur addProduct:', error);
            return { success: false, message: 'Erreur ajout produit' };
        }
    }

    // Récupérer tous les produits (pour admin)
    static async getAllProducts() {
        try {
            const products = await dbAll('SELECT * FROM products ORDER BY created_at DESC');
            return { success: true, products };
        } catch (error) {
            console.error('Erreur getAllProducts:', error);
            return { success: false, message: 'Erreur récupération produits' };
        }
    }
}

module.exports = AdminFunctions;