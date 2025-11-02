// ==================== CONFIGURATION ET SÉCURITÉ ====================

class SecurityManager {
    static sanitizeInput(input) {
        if (typeof input !== 'string') return input;
        return input
            .replace(/[<>]/g, '')
            .replace(/javascript:/gi, '')
            .replace(/on\w+=/gi, '')
            .replace(/data:/gi, '')
            .replace(/vbscript:/gi, '')
            .replace(/[\x00-\x1f\x7f-\x9f]/g, '')
            .trim();
    }

    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// ==================== API CLIENT ====================
class API {
    static csrfToken = null;
    static csrfInitialized = false;

    static async initCSRF() {
        try {
            const response = await fetch('/api/csrf-token', {
                method: 'GET',
                credentials: 'include',
                headers: { 'Accept': 'application/json' }
            });

            if (!response.ok) throw new Error(`HTTP ${response.status}`);

            const data = await response.json();
            if (data.success && data.csrfToken) {
                this.csrfToken = data.csrfToken;
                this.csrfInitialized = true;
            } else {
                throw new Error('Token CSRF non reçu');
            }
        } catch (error) {
            console.error('Erreur initialisation CSRF:', error);
            setTimeout(() => this.initCSRF(), 1000);
        }
    }

    static async request(endpoint, options = {}) {
        const config = {
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        if (!this.csrfInitialized) {
            await this.initCSRF();
        }

        if (this.csrfToken && config.method && config.method !== 'GET') {
            config.headers['X-CSRF-Token'] = this.csrfToken;
        }

        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }

        try {
            const response = await fetch(`/api${endpoint}`, config);

            if (response.status === 403) {
                const errorData = await response.json();
                if (errorData.message && errorData.message.includes('CSRF')) {
                    this.csrfInitialized = false;
                    await this.initCSRF();

                    if (this.csrfToken && config.method !== 'GET') {
                        config.headers['X-CSRF-Token'] = this.csrfToken;
                    }

                    const retryResponse = await fetch(`/api${endpoint}`, config);
                    const retryData = await retryResponse.json();
                    return retryData;
                }
            }

            if (response.status === 204) {
                return { success: true };
            }

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || `Erreur ${response.status}`);
            }

            return data;
        } catch (error) {
            console.error(`Erreur API ${endpoint}:`, error);
            throw error;
        }
    }

    // Auth
    static async login(email, password) {
        return this.request('/auth/login', {
            method: 'POST',
            body: { email, password }
        });
    }

    static async register(userData) {
        return this.request('/auth/register', {
            method: 'POST',
            body: userData
        });
    }

    static async logout() {
        return this.request('/auth/logout', { method: 'POST' });
    }

    static async verifySession() {
        return this.request('/auth/verify');
    }

    // Favoris
    static async getFavorites() {
        return this.request('/users/favorites');
    }

    static async toggleFavorite(productId) {
        return this.request(`/users/favorites/${productId}`, { method: 'POST' });
    }

    // Panier
    static async getCart() {
        return this.request('/users/cart');
    }

    static async addToCart(productId) {
        return this.request(`/users/cart/${productId}`, { method: 'POST' });
    }

    static async removeFromCart(productId) {
        return this.request(`/users/cart/${productId}`, { method: 'DELETE' });
    }

    // Admin
    static async getUsers() {
        return this.request('/admin/users');
    }

    static async updateUser(userId, userData) {
        return this.request(`/admin/users/${userId}`, {
            method: 'PUT',
            body: userData
        });
    }

    static async deleteUser(userId) {
        return this.request(`/admin/users/${userId}`, { method: 'DELETE' });
    }

    static async getStats() {
        return this.request('/admin/stats');
    }
}

// ==================== AUTHENTIFICATION ====================
class Auth {
    static currentUser = null;
    static currentSession = null;

    static async init() {
        try {
            const response = await API.verifySession();
            if (response.success) {
                this.currentUser = response.user;
                this.updateUI();
                return true;
            }
        } catch (error) {
            console.log('Aucun utilisateur connecté');
            this.currentUser = null;
            this.updateUI();
        }
        return false;
    }


    static async login(email, password) {
        try {
            const response = await API.login(email, password);
            if (response.success) {
                this.currentUser = response.user;
                this.updateUI();
                return { success: true, user: response.user };
            } else {
                return { success: false, message: response.message };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    static async register(userData) {
        try {
            const response = await API.register(userData);
            if (response.success) {
                this.currentUser = response.user;
                this.updateUI();
                return { success: true, user: response.user };
            } else {
                return { success: false, message: response.message };
            }
        } catch (error) {
            return { success: false, message: error.message };
        }
    }

    static async logout() {
        try {
            await API.logout();
        } catch (error) {
            console.error('Erreur déconnexion:', error);
        } finally {
            this.currentUser = null;
            this.currentSession = null;
            this.updateUI();
            window.location.reload();
        }
    }

    static updateUI() {
        const userMenu = document.getElementById('userMenu');
        const loginButton = document.getElementById('loginButton');
        const userName = document.getElementById('userName');
        const adminMenuItem = document.getElementById('adminMenuItem');

        if (this.currentUser) {
            // Afficher le menu utilisateur
            if (userMenu) userMenu.classList.remove('hidden');
            if (loginButton) loginButton.classList.add('hidden');
            if (userName) userName.textContent = `${this.currentUser.firstName} ${this.currentUser.lastName}`;

            // Gestion admin
            if (adminMenuItem) {
                if (this.currentUser.role === 'admin') {
                    adminMenuItem.classList.remove('hidden');
                } else {
                    adminMenuItem.classList.add('hidden');
                }
            }
        } else {
            // Cacher le menu utilisateur
            if (userMenu) userMenu.classList.add('hidden');
            if (loginButton) loginButton.classList.remove('hidden');
            if (adminMenuItem) adminMenuItem.classList.add('hidden');
        }
    }

    static isAdmin() {
        return this.currentUser && this.currentUser.role === 'admin';
    }
}

// ==================== INTERFACE UTILISATEUR ====================
class UI {
    static showNotification(message, type = 'info') {
        const sanitizedMessage = SecurityManager.sanitizeInput(message);
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 ${
            type === 'error' ? 'bg-red-500 text-white' :
                type === 'success' ? 'bg-green-500 text-white' :
                    'bg-blue-500 text-white'
        }`;
        notification.textContent = sanitizedMessage;
        notification.style.animation = 'slideIn 0.3s ease-out';

        document.body.appendChild(notification);

        setTimeout(() => {
            notification.remove();
        }, 3000);
    }

    static toggleCart() {
        const sidebar = document.getElementById('cartSidebar');
        const overlay = document.getElementById('cartOverlay');
        sidebar.classList.toggle('translate-x-full');
        overlay.classList.toggle('hidden');
    }

    static openLogin() {
        document.getElementById('loginModal').classList.remove('hidden');
        document.getElementById('signupModal').classList.add('hidden');
    }

    static closeLogin() {
        document.getElementById('loginModal').classList.add('hidden');
        document.getElementById('loginError').classList.add('hidden');
        this.clearFormData();
    }

    static openSignup() {
        document.getElementById('signupModal').classList.remove('hidden');
        document.getElementById('loginModal').classList.add('hidden');
    }

    static closeSignup() {
        document.getElementById('signupModal').classList.add('hidden');
        document.getElementById('signupError').classList.add('hidden');
        this.clearFormData();
    }

    static switchToLogin() {
        document.getElementById('signupModal').classList.add('hidden');
        document.getElementById('loginModal').classList.remove('hidden');
    }

    static showHomePage() {
        document.getElementById('mainContent').classList.remove('hidden');
        document.getElementById('favoritesPage').classList.add('hidden');
        document.getElementById('adminPanel').classList.add('hidden');

        // Scroll vers le haut
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    }

    static showFavorites() {
        if (!Auth.currentUser) {
            this.showNotification('Veuillez vous connecter pour accéder aux favoris', 'error');
            return;
        }
        document.getElementById('mainContent').classList.add('hidden');
        document.getElementById('favoritesPage').classList.remove('hidden');
        document.getElementById('adminPanel').classList.add('hidden');

        // Scroll vers le haut
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });

        this.loadFavorites();
    }


    static async loadFavorites() {
        try {
            const response = await API.getFavorites();
            this.renderFavorites(response.favorites);
        } catch (error) {
            console.error('Erreur chargement favoris:', error);
            this.showNotification('Erreur lors du chargement des favoris', 'error');
        }
    }

    static renderFavorites(favorites) {
        const favoritesGrid = document.getElementById('favoritesGrid');

        if (!favorites || favorites.length === 0) {
            favoritesGrid.innerHTML = `
            <div class="text-center py-16 col-span-full">
                <div class="text-6xl mb-4">💔</div>
                <h3 class="text-xl font-semibold text-gray-600 mb-2">Aucun favori</h3>
                <p class="text-gray-500">Ajoutez des sneakers à vos favoris pour les retrouver ici !</p>
            </div>
        `;
        } else {
            favoritesGrid.innerHTML = favorites.map(product => `
            <div class="sneaker-card rounded-2xl p-6 shadow-lg card-hover">
                <div class="text-center mb-4">
                    <div class="text-8xl mb-4">${product.image_emoji}</div>
                    <div class="text-sm text-gray-500 mb-2">${SecurityManager.sanitizeInput(product.brand)}</div>
                    <h4 class="text-xl font-bold text-gray-800 mb-2">${SecurityManager.sanitizeInput(product.name)}</h4>
                    <p class="text-gray-600 text-sm mb-4">${SecurityManager.sanitizeInput(product.description)}</p>
                </div>
                <div class="flex justify-between items-center mb-4">
                    <div class="price-tag text-white px-3 py-1 rounded-full text-sm font-bold">
                        ${product.price}€
                    </div>
                </div>
                <div class="flex gap-2">
                    <button onclick="App.toggleFavorite(${product.id}, '${SecurityManager.escapeHtml(product.name)}', ${product.price}, '${SecurityManager.escapeHtml(product.brand)}', '${SecurityManager.escapeHtml(product.description)}', '${product.image_emoji}')" 
                            class="favorite-btn flex-shrink-0 p-3 border border-red-300 rounded-lg hover:bg-gray-50 transition duration-200 text-red-500"
                            data-product-name="${SecurityManager.escapeHtml(product.name)}">
                        <span class="text-xl">❤️</span>
                    </button>
                    <button onclick="App.addToCart('${SecurityManager.escapeHtml(product.name)}', ${product.price})" 
                            class="flex-1 bg-blue-600 hover:bg-blue-700 text-white py-3 rounded-lg font-medium transition duration-200">
                        Ajouter au Panier
                    </button>
                </div>
            </div>
        `).join('');

            App.updateFavoriteButtons();
        }
    }

    static showAdminPanel() {
        if (!Auth.isAdmin()) {
            this.showNotification('Accès non autorisé', 'error');
            return;
        }
        document.getElementById('mainContent').classList.add('hidden');
        document.getElementById('favoritesPage').classList.add('hidden');
        document.getElementById('adminPanel').classList.remove('hidden');
        AdminPanel.loadAdminPanel();
    }

    static clearFormData() {
        const sensitiveFields = ['loginPassword', 'signupPassword', 'signupConfirmPassword'];
        sensitiveFields.forEach(fieldId => {
            const field = document.getElementById(fieldId);
            if (field) field.value = '';
        });
    }
}

// ==================== PANEL ADMIN ====================
class AdminPanel {
    static async loadAdminPanel() {
        if (!Auth.currentUser) {
            UI.showNotification('Veuillez vous connecter', 'error');
            return;
        }

        if (!Auth.isAdmin()) {
            UI.showNotification('Accès réservé aux administrateurs', 'error');
            return;
        }

        this.showLoading();

        try {
            const users = await this.loadUsers();
            const stats = await this.loadStats();
            this.renderUsers(users);
            this.renderStats(stats);
        } catch (error) {
            console.error('Erreur chargement panel admin:', error);
            this.showError();
        }
    }

    static async loadUsers() {
        try {
            const response = await API.getUsers();
            return response.users || [];
        } catch (error) {
            console.error('Erreur chargement utilisateurs:', error);
            return [];
        }
    }

    static renderUsers(users) {
        const tbody = document.getElementById('usersTableBody');
        if (!tbody) return;

        if (!users || users.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-6 py-8 text-center text-gray-500">
                        Aucun utilisateur trouvé
                    </td>
                </tr>
            `;
            return;
        }

        tbody.innerHTML = users.map(user => {
            const isCurrentUser = user.id === Auth.currentUser.id;
            return `
            <tr class="hover:bg-gray-50 border-b">
                <td class="px-6 py-4">
                    <div class="font-medium">
                        ${user.first_name} ${user.last_name}
                        ${isCurrentUser ? ' <span class="text-blue-500 text-sm">(Vous)</span>' : ''}
                    </div>
                </td>
                <td class="px-6 py-4 text-sm">${user.email}</td>
                <td class="px-6 py-4">
                    <span class="px-2 py-1 text-xs rounded-full ${
                user.role === 'admin' ? 'bg-purple-100 text-purple-800' : 'bg-blue-100 text-blue-800'
            }">
                        ${user.role === 'admin' ? 'Admin' : 'User'}
                    </span>
                </td>
                <td class="px-6 py-4 text-sm text-gray-500">
                    ${new Date(user.created_at).toLocaleDateString('fr-FR')}
                </td>
                <td class="px-6 py-4">
                    ${!isCurrentUser ? `
                        <div class="flex flex-col space-y-2">
                            <div class="flex space-x-2">
                                ${user.role === 'user' ? `
                                    <button onclick="AdminPanel.promoteUser(${user.id})" 
                                            class="px-3 py-2 bg-purple-500 text-white text-xs rounded-lg hover:bg-purple-600 transition duration-200 flex items-center">
                                        <span class="mr-1">👑</span> Promouvoir
                                    </button>
                                ` : `
                                    <button onclick="AdminPanel.demoteUser(${user.id})" 
                                            class="px-3 py-2 bg-blue-500 text-white text-xs rounded-lg hover:bg-blue-600 transition duration-200 flex items-center">
                                        <span class="mr-1">👤</span> Rétrograder
                                    </button>
                                `}
                                <button onclick="AdminPanel.deleteUser(${user.id})" 
                                        class="px-3 py-2 bg-red-600 text-white text-xs rounded-lg hover:bg-red-700 transition duration-200 flex items-center">
                                    <span class="mr-1">🗑️</span> Supprimer
                                </button>
                            </div>
                        </div>
                    ` : `
                        <span class="text-gray-400 text-sm">Compte actuel</span>
                    `}
                </td>
            </tr>
            `;
        }).join('');
    }

    static async promoteUser(userId) {
        if (!confirm('Promouvoir cet utilisateur en administrateur ?')) return;
        try {
            const response = await API.updateUser(userId, { role: 'admin' });
            if (response.success) {
                UI.showNotification('Utilisateur promu administrateur avec succès!', 'success');
                this.loadAdminPanel();
            } else {
                UI.showNotification(response.message || 'Erreur lors de la promotion', 'error');
            }
        } catch (error) {
            console.error('Erreur promotion:', error);
            UI.showNotification('Erreur lors de la promotion', 'error');
        }
    }

    static async demoteUser(userId) {
        if (!confirm('Rétrograder cet utilisateur en utilisateur standard ?')) return;
        try {
            const response = await API.updateUser(userId, { role: 'user' });
            if (response.success) {
                UI.showNotification('Utilisateur rétrogradé avec succès!', 'success');
                this.loadAdminPanel();
            } else {
                UI.showNotification(response.message || 'Erreur lors de la rétrogradation', 'error');
            }
        } catch (error) {
            console.error('Erreur rétrogradation:', error);
            UI.showNotification('Erreur lors de la rétrogradation', 'error');
        }
    }

    static async deleteUser(userId) {
        if (!confirm('Êtes-vous sûr de vouloir supprimer définitivement cet utilisateur ? Cette action est irréversible.')) return;
        try {
            const response = await API.deleteUser(userId);
            if (response.success) {
                UI.showNotification('Utilisateur supprimé avec succès!', 'success');
                this.loadAdminPanel();
            } else {
                UI.showNotification(response.message || 'Erreur lors de la suppression', 'error');
            }
        } catch (error) {
            console.error('Erreur suppression:', error);
            UI.showNotification('Erreur lors de la suppression', 'error');
        }
    }

    static showLoading() {
        const tbody = document.getElementById('usersTableBody');
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-6 py-8 text-center text-gray-500">
                        Chargement...
                    </td>
                </tr>
            `;
        }
    }

    static showError() {
        const tbody = document.getElementById('usersTableBody');
        if (tbody) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="px-6 py-8 text-center text-gray-500">
                        Erreur lors du chargement des données
                        <br>
                        <button onclick="AdminPanel.loadAdminPanel()" class="mt-2 px-3 py-1 bg-blue-500 text-white rounded text-sm">
                            Réessayer
                        </button>
                    </td>
                </tr>
            `;
        }
    }

    static async loadStats() {
        try {
            const response = await API.getStats();
            return response.stats || {};
        } catch (error) {
            console.error('Erreur chargement stats:', error);
            return {};
        }
    }

    static renderStats(stats) {
        const elements = {
            'totalUsers': stats.totalUsers || 0,
            'totalAdmins': stats.totalAdmins || 0,
            'totalRegularUsers': stats.totalRegularUsers || 0,
            'activeUsers': stats.activeUsers || 0
        };

        for (const [id, value] of Object.entries(elements)) {
            const element = document.getElementById(id);
            if (element) element.textContent = value;
        }
    }
}

// ==================== APPLICATION PRINCIPALE ====================
class App {
    static favorites = new Map();
    static cart = new Map();

    static async init() {
        try {
            await API.initCSRF();

            await Auth.init();

            if (Auth.currentUser) {
                await this.loadUserData();
            }

        } catch (error) {
            console.error('Erreur initialisation App:', error);
        }
    }

    static async toggleFavorite(productId, name, price, brand, description, emoji) {
        if (!Auth.currentUser) {
            UI.showNotification('Veuillez vous connecter pour ajouter aux favoris', 'error');
            return;
        }

        try {
            // CORRECTION : Utiliser le nom encodé
            const encodedName = encodeURIComponent(name);
            const response = await API.toggleFavorite(encodedName);

            console.log('Réponse toggleFavorite:', response); // DEBUG

            if (response.success) {
                if (response.isFavorite) {
                    // AJOUT aux favoris
                    this.favorites.set(name, {
                        id: productId,
                        name: name,
                        price: price,
                        brand: brand,
                        description: description,
                        image_emoji: emoji
                    });
                    UI.showNotification('❤️ Ajouté aux favoris!', 'success');
                } else {
                    // RETIRER des favoris
                    this.favorites.delete(name);
                    UI.showNotification('💔 Retiré des favoris', 'info');
                }

                this.updateFavoritesCount();
                this.updateFavoriteButtons();

                // CORRECTION : Recharger l'affichage si on est sur la page favoris
                if (document.getElementById('favoritesPage') && !document.getElementById('favoritesPage').classList.contains('hidden')) {
                    UI.loadFavorites();
                }
            } else {
                UI.showNotification(response.message || 'Erreur avec les favoris', 'error');
            }
        } catch (error) {
            console.error('Erreur toggleFavorite:', error);
            UI.showNotification('Erreur lors de la mise à jour des favoris', 'error');
        }
    }


    static async addToCart(name, price) {
        if (!Auth.currentUser) {
            UI.showNotification('Veuillez vous connecter pour ajouter au panier', 'error');
            return;
        }

        try {
            // CORRECTION : Encoder le nom
            const encodedName = encodeURIComponent(name);
            const response = await API.addToCart(encodedName);

            console.log('Réponse addToCart:', response); // DEBUG

            if (response.success) {
                const existingItem = this.cart.get(name);
                if (existingItem) {
                    existingItem.quantity += 1;
                } else {
                    this.cart.set(name, {
                        name: name,
                        price: parseFloat(price) || 0,
                        quantity: 1
                    });
                }

                this.updateCartCount();
                this.updateCartDisplay();
                UI.showNotification('🛒 Produit ajouté au panier!', 'success');
            } else {
                UI.showNotification(response.message || 'Erreur avec le panier', 'error');
            }
        } catch (error) {
            console.error('Erreur addToCart:', error);
            UI.showNotification('Erreur lors de l\'ajout au panier', 'error');
        }
    }

    static async removeFromCart(name) {
        if (!Auth.currentUser) {
            UI.showNotification('Veuillez vous connecter pour modifier le panier', 'error');
            return;
        }

        try {
            // Encoder le nom du produit pour l'URL
            const encodedName = encodeURIComponent(name);
            const response = await API.removeFromCart(encodedName);

            if (response.success) {
                this.cart.delete(name);
                this.updateCartCount();
                this.updateCartDisplay();
                UI.showNotification('Produit retiré du panier', 'success');
            } else {
                UI.showNotification(response.message || 'Erreur lors de la suppression', 'error');
            }
        } catch (error) {
            console.error('Erreur removeFromCart:', error);
            UI.showNotification('Erreur lors de la suppression du panier', 'error');
        }
    }

    static clearCart() {
        this.cart.clear();
        this.updateCartCount();
        this.updateCartDisplay();
    }

    static updateFavoritesCount() {
        const count = this.favorites.size;
        const badge = document.getElementById('favoritesCount');
        if (badge) {
            badge.textContent = count;
            badge.classList.toggle('hidden', count === 0);
        }
    }

    static updateCartCount() {
        const count = Array.from(this.cart.values()).reduce((total, item) => total + (item.quantity || 1), 0);
        const badge = document.getElementById('cartCount');
        if (badge) {
            badge.textContent = count;
            badge.classList.toggle('hidden', count === 0);
        }
    }

    // Mise à jour des boutons favoris
    static updateFavoriteButtons() {
        document.querySelectorAll('.favorite-btn').forEach(btn => {
            const productName = btn.getAttribute('data-product-name');
            if (productName) {
                const heart = btn.querySelector('span');
                if (heart) {
                    if (this.favorites.has(productName)) {
                        heart.textContent = '❤️';
                        btn.classList.add('text-red-500', 'border-red-300');
                        btn.classList.remove('text-gray-400');
                    } else {
                        heart.textContent = '🤍';
                        btn.classList.remove('text-red-500', 'border-red-300');
                        btn.classList.add('text-gray-400');
                    }
                }
            }
        });
    }

    static updateCartDisplay() {
        const cartItemsContainer = document.getElementById('cartItems');
        const cartTotalElement = document.getElementById('cartTotal');
        const checkoutButton = document.getElementById('checkoutButton');
        const emptyCartMessage = document.getElementById('emptyCartMessage');

        if (!cartItemsContainer) return;

        if (this.cart.size === 0) {
            cartItemsContainer.innerHTML = `
                <div class="text-center py-8">
                    <div class="text-6xl mb-4">🛒</div>
                    <p class="text-gray-500">Votre panier est vide</p>
                </div>
            `;
            if (cartTotalElement) cartTotalElement.textContent = '0.00€';
            if (checkoutButton) checkoutButton.classList.add('hidden');
            if (emptyCartMessage) emptyCartMessage.classList.remove('hidden');
            return;
        }

        cartItemsContainer.innerHTML = '';
        let total = 0;

        this.cart.forEach((item, productName) => {
            const price = parseFloat(item.price) || 0;
            const quantity = parseInt(item.quantity) || 1;
            const itemTotal = price * quantity;
            total += itemTotal;

            const cartItem = document.createElement('div');
            cartItem.className = 'flex justify-between items-center py-4 border-b border-gray-200';
            cartItem.innerHTML = `
                <div class="flex items-center space-x-3 flex-1">
                    <div class="flex-1">
                        <h4 class="font-semibold text-gray-800">${SecurityManager.escapeHtml(item.name)}</h4>
                        <p class="text-gray-600 text-sm">${price.toFixed(2)}€ × ${quantity}</p>
                    </div>
                </div>
                <div class="flex items-center space-x-3">
                    <p class="font-semibold text-gray-900">${itemTotal.toFixed(2)}€</p>
                    <button onclick="removeFromCart('${SecurityManager.escapeHtml(item.name)}')" 
                            class="text-red-500 hover:text-red-700 transition duration-200 p-2 rounded-lg hover:bg-red-50"
                            title="Supprimer du panier">
                        <span class="text-lg">🗑️</span>
                    </button>
                </div>
            `;
            cartItemsContainer.appendChild(cartItem);
        });

        if (cartTotalElement) cartTotalElement.textContent = total.toFixed(2) + '€';
        if (checkoutButton) checkoutButton.classList.remove('hidden');
        if (emptyCartMessage) emptyCartMessage.classList.add('hidden');
    }

    static async loadUserData() {
        try {
            const favoritesResponse = await API.getFavorites();
            this.favorites.clear();
            if (favoritesResponse.success && favoritesResponse.favorites) {
                favoritesResponse.favorites.forEach(fav => {
                    this.favorites.set(fav.name, {
                        name: fav.name || '',
                        price: parseFloat(fav.price) || 0,
                        brand: fav.brand || '',
                        description: fav.description || '',
                        image_emoji: fav.image_emoji || '👟'
                    });
                });
            }

            const cartResponse = await API.getCart();
            this.cart.clear();
            if (cartResponse.success && cartResponse.cartItems) {
                cartResponse.cartItems.forEach(item => {
                    this.cart.set(item.name, {
                        name: item.name || '',
                        price: parseFloat(item.price) || 0,
                        quantity: parseInt(item.quantity) || 1
                    });
                });
            }

            this.updateFavoritesCount();
            this.updateCartCount();
            this.updateCartDisplay();
            this.updateFavoriteButtons();

            console.log('Données utilisateur chargées');
        } catch (error) {
            console.error('Erreur chargement données utilisateur:', error);
        }
    }

    static async checkout() {
        if (!Auth.currentUser) {
            UI.showNotification('Veuillez vous connecter pour passer commande', 'error');
            return;
        }

        if (this.cart.size === 0) {
            UI.showNotification('Votre panier est vide', 'error');
            return;
        }

        try {
            let total = 0;
            this.cart.forEach(item => {
                const price = parseFloat(item.price) || 0;
                const quantity = parseInt(item.quantity) || 1;
                total += price * quantity;
            });

            UI.showNotification(`Commande de ${total.toFixed(2)}€ en cours de traitement...`, 'info');
            await new Promise(resolve => setTimeout(resolve, 1500));

            this.clearCart();
            UI.showNotification('Commande passée avec succès!', 'success');
            UI.toggleCart();

        } catch (error) {
            console.error('Erreur commande:', error);
            UI.showNotification('Erreur lors de la commande', 'error');
        }
    }
}

// ==================== FONCTIONS GLOBALES ====================
function toggleFavorite(productId, name, price, brand, description, emoji) {
    App.toggleFavorite(productId, name, price, brand, description, emoji);
}

function addToCart(name, price) {
    App.addToCart(name, price);
}

async function removeFromCart(name) {
    await App.removeFromCart(name);
}


function navigateToAccueil() {
    UI.showHomePage();
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function navigateToNouveautes() {
    UI.showHomePage();
    const section = document.getElementById('nouveautes');
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function navigateToMarques() {
    UI.showHomePage();
    const section = document.getElementById('marques');
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function showHomePage() {
    UI.showHomePage();
}

function showFavorites() {
    UI.showFavorites();
}

function showAdminPanel() {
    UI.showAdminPanel();
}

function openLogin() {
    UI.openLogin();
}

function closeLogin() {
    UI.closeLogin();
}

function openSignup() {
    UI.openSignup();
}

function closeSignup() {
    UI.closeSignup();
}

function switchToLogin() {
    UI.switchToLogin();
}

function toggleCart() {
    UI.toggleCart();
}

function toggleUserDropdown() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        // CORRECTION : Basculer simplement la classe 'hidden'
        dropdown.classList.toggle('hidden');
    }
}

function closeUserDropdown() {
    const dropdown = document.getElementById('userDropdown');
    if (dropdown) {
        dropdown.classList.add('hidden');
    }
}

// Fermer le dropdown en cliquant ailleurs
document.addEventListener('click', (e) => {
    const userMenu = document.getElementById('userMenu');
    const dropdown = document.getElementById('userDropdown');

    if (userMenu && dropdown && !userMenu.contains(e.target)) {
        closeUserDropdown();
    }
});

function showProfile() {
    UI.showNotification('Page profil en développement', 'info');
}

function logout() {
    Auth.logout();
}

function clearFormData() {
    UI.clearFormData();
}

// ==================== GESTION DES FORMULAIRES ====================
async function handleLoginForm() {
    const email = document.getElementById('loginEmail')?.value;
    const password = document.getElementById('loginPassword')?.value;
    const errorDiv = document.getElementById('loginError');

    if (!email || !password) {
        if (errorDiv) {
            errorDiv.textContent = 'Email et mot de passe requis';
            errorDiv.classList.remove('hidden');
        }
        return;
    }

    try {
        const result = await Auth.login(email, password);
        if (result.success) {
            UI.closeLogin();
            UI.showNotification('Connexion réussie!', 'success');
            await App.loadUserData();
            App.updateFavoriteButtons();
            App.updateCartDisplay();
        } else {
            if (errorDiv) {
                errorDiv.textContent = result.message;
                errorDiv.classList.remove('hidden');
            }
        }
    } catch (error) {
        console.error('Erreur login:', error);
        if (errorDiv) {
            errorDiv.textContent = error.message || 'Erreur de connexion';
            errorDiv.classList.remove('hidden');
        }
    }
}

async function handleSignupForm() {
    const formData = {
        email: document.getElementById('signupEmail')?.value,
        password: document.getElementById('signupPassword')?.value,
        firstName: document.getElementById('signupFirstName')?.value,
        lastName: document.getElementById('signupLastName')?.value
    };
    const errorDiv = document.getElementById('signupError');

    if (!formData.email || !formData.password || !formData.firstName || !formData.lastName) {
        if (errorDiv) {
            errorDiv.textContent = 'Tous les champs sont requis';
            errorDiv.classList.remove('hidden');
        }
        return;
    }

    try {
        const result = await Auth.register(formData);
        if (result.success) {
            UI.closeSignup();
            UI.showNotification('Inscription réussie!', 'success');
            await App.loadUserData();
        } else {
            if (errorDiv) {
                errorDiv.textContent = result.message;
                errorDiv.classList.remove('hidden');
            }
        }
    } catch (error) {
        console.error('Erreur signup:', error);
        if (errorDiv) {
            errorDiv.textContent = error.message || 'Erreur d\'inscription';
            errorDiv.classList.remove('hidden');
        }
    }
}

// ==================== INITIALISATION ====================
document.addEventListener('DOMContentLoaded', function() {

    // Formulaires
    const loginForm = document.getElementById('loginForm');
    const signupForm = document.getElementById('signupForm');

    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleLoginForm();
        });
    }

    if (signupForm) {
        signupForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            await handleSignupForm();
        });
    }

    // Fermeture des dropdowns en cliquant ailleurs
    document.addEventListener('click', (e) => {
        const userMenu = document.getElementById('userMenu');
        const dropdown = document.getElementById('userDropdown');

        if (userMenu && dropdown && !userMenu.contains(e.target)) {
            closeUserDropdown();
        }
    });

    // Initialisation de l'application
    App.init();
});
