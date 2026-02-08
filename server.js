const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize SQLite database
const db = new Database('dondadtech.db');

// Create tables if they don't exist
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        password TEXT,
        role TEXT DEFAULT 'user',
        createdAt DATETIME
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        category TEXT,
        price REAL,
        image TEXT,
        desc TEXT,
        stock INTEGER DEFAULT 0
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS carts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        productId INTEGER,
        qty INTEGER DEFAULT 1
    )
`);

db.exec(`
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER,
        items TEXT,
        total REAL,
        shippingAddress TEXT,
        paymentMethod TEXT,
        status TEXT DEFAULT 'pending',
        createdAt DATETIME
    )
`);

// Seed default admin if not exists
const adminExists = db.prepare('SELECT * FROM users WHERE email = ?').get('admin@dondad.com');
if (!adminExists) {
    db.prepare(`
        INSERT INTO users (name, email, phone, password, role, createdAt)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run('Admin', 'admin@dondad.com', '08000000000', 'admin123', 'admin', new Date().toISOString());
}

// Seed default products if none exist
const productCount = db.prepare('SELECT COUNT(*) as count FROM products').get();
if (productCount.count === 0) {
    const products = [
        { name: "iPhone 11", category: "phones", price: 150000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "Triple-camera, A13 chip", stock: 10 },
        { name: "iPhone XS", category: "phones", price: 120000, image: "xs.png", desc: "Super Retina OLED", stock: 8 },
        { name: "iPhone XR", category: "phones", price: 100000, image: "xs.png", desc: "Liquid Retina, Face ID", stock: 5 },
        { name: "iPhone X", category: "phones", price: 90000, image: "xs.png", desc: "First OLED iPhone", stock: 3 },
        { name: "MacBook Pro 14\"", category: "laptops", price: 450000, image: "hero img.png", desc: "M3 Pro chip, 18GB RAM", stock: 5 },
        { name: "MacBook Air M2", category: "laptops", price: 350000, image: "hero img.png", desc: "M2 chip, 8GB RAM", stock: 7 },
        { name: "iPad Pro 12.9\"", category: "tablets", price: 280000, image: "xs.png", desc: "M2 chip, 128GB", stock: 6 },
        { name: "AirPods Pro", category: "accessories", price: 45000, image: "xs.png", desc: "Active Noise Cancellation", stock: 20 }
    ];
    
    const insertProduct = db.prepare(`
        INSERT INTO products (name, category, price, image, desc, stock)
        VALUES (?, ?, ?, ?, ?, ?)
    `);
    
    for (const p of products) {
        insertProduct.run(p.name, p.category, p.price, p.image, p.desc, p.stock);
    }
}

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// ============ AUTH ROUTES ============

// Register
app.post('/api/register', (req, res) => {
    const { name, email, password, phone } = req.body;
    
    try {
        const result = db.prepare('INSERT INTO users (name, email, phone, password, role, createdAt) VALUES (?, ?, ?, ?, ?, ?)')
            .run(name, email, phone || '', password, email === 'admin@dondad.com' ? 'admin' : 'user', new Date().toISOString());
        
        res.json({ 
            message: 'Registration successful', 
            user: { id: result.lastInsertRowid, name, email, role: email === 'admin@dondad.com' ? 'admin' : 'user' } 
        });
    } catch (error) {
        if (error.message.includes('UNIQUE constraint failed')) {
            res.status(400).json({ error: 'Email already registered' });
        } else {
            res.status(500).json({ error: 'Registration failed' });
        }
    }
});

// Login
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    const user = db.prepare('SELECT * FROM users WHERE email = ? AND password = ?').get(email, password);
    
    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    res.json({ 
        message: 'Login successful', 
        user: { id: user.id, name: user.name, email: user.email, role: user.role } 
    });
});

// ============ PRODUCT ROUTES ============

// Get all products
app.get('/api/products', (req, res) => {
    const { category, search } = req.query;
    let query = 'SELECT * FROM products WHERE 1=1';
    const params = [];
    
    if (category && category !== 'all') {
        query += ' AND category = ?';
        params.push(category);
    }
    
    if (search) {
        query += ' AND (name LIKE ? OR desc LIKE ?)';
        params.push(`%${search}%`, `%${search}%`);
    }
    
    query += ' ORDER BY id DESC';
    
    const products = db.prepare(query).all(...params);
    res.json(products);
});

// Get single product
app.get('/api/products/:id', (req, res) => {
    const product = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
    if (!product) {
        return res.status(404).json({ error: 'Product not found' });
    }
    res.json(product);
});

// Add product (admin only)
app.post('/api/products', (req, res) => {
    const { name, category, price, image, desc, stock } = req.body;
    
    const result = db.prepare(`
        INSERT INTO products (name, category, price, image, desc, stock)
        VALUES (?, ?, ?, ?, ?, ?)
    `).run(name, category, parseFloat(price), image || 'logo.png', desc, parseInt(stock) || 0);
    
    const newProduct = db.prepare('SELECT * FROM products WHERE id = ?').get(result.lastInsertRowid);
    res.json({ message: 'Product added', product: newProduct });
});

// Update product (admin only)
app.put('/api/products/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const { name, category, price, image, desc, stock } = req.body;
    
    db.prepare(`
        UPDATE products SET name = ?, category = ?, price = ?, image = ?, desc = ?, stock = ?
        WHERE id = ?
    `).run(name, category, parseFloat(price), image || 'logo.png', desc, parseInt(stock) || 0, id);
    
    const updatedProduct = db.prepare('SELECT * FROM products WHERE id = ?').get(id);
    res.json({ message: 'Product updated', product: updatedProduct });
});

// Delete product (admin only)
app.delete('/api/products/:id', (req, res) => {
    const id = parseInt(req.params.id);
    
    db.prepare('DELETE FROM products WHERE id = ?').run(id);
    res.json({ message: 'Product deleted' });
});

// ============ CART ROUTES ============

// Get cart
app.get('/api/cart/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const cartItems = db.prepare(`
        SELECT c.*, p.name, p.price, p.image 
        FROM carts c 
        JOIN products p ON c.productId = p.id 
        WHERE c.userId = ?
    `).all(userId);
    res.json(cartItems);
});

// Add to cart
app.post('/api/cart', (req, res) => {
    const { userId, productId, qty } = req.body;
    
    const existing = db.prepare('SELECT * FROM carts WHERE userId = ? AND productId = ?').get(userId, productId);
    
    if (existing) {
        db.prepare('UPDATE carts SET qty = qty + ? WHERE id = ?').run(qty || 1, existing.id);
    } else {
        db.prepare('INSERT INTO carts (userId, productId, qty) VALUES (?, ?, ?)').run(userId, productId, qty || 1);
    }
    
    const cart = db.prepare(`
        SELECT c.*, p.name, p.price, p.image 
        FROM carts c 
        JOIN products p ON c.productId = p.id 
        WHERE c.userId = ?
    `).all(userId);
    res.json({ message: 'Added to cart', cart });
});

// Update cart item
app.put('/api/cart/:userId/:productId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const productId = parseInt(req.params.productId);
    const { qty } = req.body;
    
    if (qty <= 0) {
        db.prepare('DELETE FROM carts WHERE userId = ? AND productId = ?').run(userId, productId);
    } else {
        db.prepare('UPDATE carts SET qty = ? WHERE userId = ? AND productId = ?').run(qty, userId, productId);
    }
    
    const cart = db.prepare(`
        SELECT c.*, p.name, p.price, p.image 
        FROM carts c 
        JOIN products p ON c.productId = p.id 
        WHERE c.userId = ?
    `).all(userId);
    res.json({ message: 'Cart updated', cart });
});

// Remove from cart
app.delete('/api/cart/:userId/:productId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const productId = parseInt(req.params.productId);
    
    db.prepare('DELETE FROM carts WHERE userId = ? AND productId = ?').run(userId, productId);
    
    const cart = db.prepare(`
        SELECT c.*, p.name, p.price, p.image 
        FROM carts c 
        JOIN products p ON c.productId = p.id 
        WHERE c.userId = ?
    `).all(userId);
    res.json({ message: 'Item removed', cart });
});

// Clear cart
app.delete('/api/cart/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    db.prepare('DELETE FROM carts WHERE userId = ?').run(userId);
    res.json({ message: 'Cart cleared' });
});

// ============ ORDER ROUTES ============

// Create order
app.post('/api/orders', (req, res) => {
    const { userId, shippingAddress, paymentMethod } = req.body;
    
    const cartItems = db.prepare(`
        SELECT c.*, p.name, p.price 
        FROM carts c 
        JOIN products p ON c.productId = p.id 
        WHERE c.userId = ?
    `).all(userId);
    
    if (cartItems.length === 0) {
        return res.status(400).json({ error: 'Cart is empty' });
    }
    
    const items = cartItems.map(item => ({
        productId: item.productId,
        name: item.name,
        price: item.price,
        qty: item.qty
    }));
    
    const total = items.reduce((sum, item) => sum + (item.price * item.qty), 0);
    
    const result = db.prepare(`
        INSERT INTO orders (userId, items, total, shippingAddress, paymentMethod, status, createdAt)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, JSON.stringify(items), total, shippingAddress, paymentMethod, 'pending', new Date().toISOString());
    
    // Clear cart
    db.prepare('DELETE FROM carts WHERE userId = ?').run(userId);
    
    res.json({ message: 'Order created', order: { id: result.lastInsertRowid, items, total, status: 'pending' } });
});

// Get user orders
app.get('/api/orders/:userId', (req, res) => {
    const userId = parseInt(req.params.userId);
    const orders = db.prepare('SELECT * FROM orders WHERE userId = ? ORDER BY createdAt DESC').all(userId);
    
    const formattedOrders = orders.map(order => ({
        ...order,
        items: JSON.parse(order.items)
    }));
    
    res.json(formattedOrders);
});

// Get all orders (admin)
app.get('/api/orders', (req, res) => {
    const orders = db.prepare('SELECT * FROM orders ORDER BY createdAt DESC').all();
    const formattedOrders = orders.map(order => ({
        ...order,
        items: JSON.parse(order.items)
    }));
    res.json(formattedOrders);
});

// Update order status (admin)
app.put('/api/orders/:id/status', (req, res) => {
    const id = parseInt(req.params.id);
    const { status } = req.body;
    
    db.prepare('UPDATE orders SET status = ? WHERE id = ?').run(status, id);
    
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(id);
    res.json({ message: 'Order status updated', order });
});

// ============ USER ROUTES ============

// Get all users (admin)
app.get('/api/users', (req, res) => {
    const users = db.prepare('SELECT id, name, email, role FROM users').all();
    res.json(users);
});

// Serve static files for SPA
app.use(express.static(path.join(__dirname)));

// Explicitly serve HTML pages
app.get('/admin.html', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));
app.get('/login.html', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register.html', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));
app.get('/cart.html', (req, res) => res.sendFile(path.join(__dirname, 'cart.html')));
app.get('/checkout.html', (req, res) => res.sendFile(path.join(__dirname, 'checkout.html')));
app.get('/product.html', (req, res) => res.sendFile(path.join(__dirname, 'product.html')));
app.get('/shop.html', (req, res) => res.sendFile(path.join(__dirname, 'shop.html')));
app.get('/index.html', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// SPA fallback for unknown routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log('Database: dondadtech.db (SQLite)');
});
