/* ========================================
   PAJAY GADGETS - SIMPLE EXPRESS SERVER
   Lightweight Backend for Development
   ======================================== */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from root directory
app.use(express.static(__dirname));

// ========================================
// PRODUCT DATA - 24 Products
// ========================================
const products = [
    // Phones (8 products)
    { _id: "1", id: 1, name: "iPhone 13 Pro Max", category: "phones", price: 450000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "256GB, A15 chip, triple camera system, ProMotion display" },
    { _id: "2", id: 2, name: "iPhone 13 Pro", category: "phones", price: 400000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "256GB, A15 chip, triple camera, ProMotion display" },
    { _id: "3", id: 3, name: "iPhone 13", category: "phones", price: 350000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A15 chip, dual camera, Super Retina XDR" },
    { _id: "4", id: 4, name: "iPhone 12 Pro Max", category: "phones", price: 320000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A14 chip, triple camera, 5G capable" },
    { _id: "5", id: 5, name: "iPhone 12", category: "phones", price: 280000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A14 chip, dual camera, OLED display" },
    { _id: "6", id: 6, name: "iPhone 11", category: "phones", price: 220000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "64GB, A13 chip, dual camera, Liquid Retina display" },
    { _id: "7", id: 7, name: "iPhone XS Max", category: "phones", price: 180000, image: "xs.png", desc: "64GB, A12 chip, dual camera, OLED display" },
    { _id: "8", id: 8, name: "iPhone XR", category: "phones", price: 150000, image: "xs.png", desc: "64GB, A12 chip, single camera, Face ID" },
    
    // Laptops (5 products)
    { _id: "9", id: 9, name: "MacBook Pro 14 inch", category: "laptops", price: 850000, image: "hero img.png", desc: "M1 Pro chip, 16GB RAM, 512GB SSD, Liquid Retina XDR" },
    { _id: "10", id: 10, name: "MacBook Air M2", category: "laptops", price: 650000, image: "hero img.png", desc: "M2 chip, 8GB RAM, 256GB SSD, 13.6-inch display" },
    { _id: "11", id: 11, name: "Dell XPS 13", category: "laptops", price: 550000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD, 13.4-inch FHD+" },
    { _id: "12", id: 12, name: "HP Spectre x360", category: "laptops", price: 480000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD, 2-in-1 touchscreen" },
    { _id: "13", id: 13, name: "Lenovo ThinkPad X1", category: "laptops", price: 520000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD, business laptop" },
    
    // Tablets (4 products)
    { _id: "14", id: 14, name: "iPad Pro 12.9 inch", category: "tablets", price: 550000, image: "hero img.png", desc: "M1 chip, 128GB, WiFi, Liquid Retina XDR display" },
    { _id: "15", id: 15, name: "iPad Air", category: "tablets", price: 350000, image: "hero img.png", desc: "M1 chip, 64GB, WiFi, 10.9-inch display" },
    { _id: "16", id: 16, name: "iPad 10th Gen", category: "tablets", price: 250000, image: "hero img.png", desc: "A14 chip, 64GB, WiFi, 10.9-inch Liquid Retina" },
    { _id: "17", id: 17, name: "Samsung Galaxy Tab S8", category: "tablets", price: 380000, image: "hero img.png", desc: "Snapdragon 8 Gen 1, 128GB, 11-inch display" },
    
    // Accessories (7 products)
    { _id: "18", id: 18, name: "AirPods Pro", category: "accessories", price: 120000, image: "Airpods-removebg-preview.png", desc: "Active noise cancellation, Adaptive Transparency" },
    { _id: "19", id: 19, name: "AirPods 3", category: "accessories", price: 85000, image: "Airpods-removebg-preview.png", desc: "Spatial audio, wireless charging, force sensor" },
    { _id: "20", id: 20, name: "iPhone Charger 20W", category: "accessories", price: 15000, image: "xs.png", desc: "Fast charging adapter, USB-C to Lightning" },
    { _id: "21", id: 21, name: "USB-C Cable", category: "accessories", price: 5000, image: "xs.png", desc: "1m braided cable, fast charging support" },
    { _id: "22", id: 22, name: "Phone Case iPhone 13", category: "accessories", price: 8000, image: "xs.png", desc: "Silicone case, various colors, shock protection" },
    { _id: "23", id: 23, name: "Power Bank 20000mAh", category: "accessories", price: 25000, image: "xs.png", desc: "Fast charging, dual USB output, portable" },
    { _id: "24", id: 24, name: "Screen Protector", category: "accessories", price: 3000, image: "xs.png", desc: "Tempered glass, pack of 2, easy installation" }
];

// In-memory cart storage (for demo purposes)
const carts = {};

// ========================================
// API ENDPOINTS
// ========================================

// GET /api/products - Get all products with optional filtering
app.get('/api/products', (req, res) => {
    try {
        let result = [...products];
        
        // Filter by category
        const { category, cat } = req.query;
        const categoryFilter = category || cat;
        if (categoryFilter && categoryFilter !== 'all') {
            result = result.filter(p => p.category === categoryFilter);
        }
        
        // Search filter
        const { search, q, query } = req.query;
        const searchTerm = search || q || query;
        if (searchTerm) {
            const term = searchTerm.toLowerCase();
            result = result.filter(p => 
                p.name.toLowerCase().includes(term) ||
                (p.desc && p.desc.toLowerCase().includes(term)) ||
                (p.category && p.category.toLowerCase().includes(term))
            );
        }
        
        // Sorting
        const { sort, order } = req.query;
        if (sort) {
            const sortOrder = order === 'asc' ? 1 : -1;
            result.sort((a, b) => {
                if (sort === 'price') {
                    return (a.price - b.price) * sortOrder;
                }
                if (sort === 'name') {
                    return a.name.localeCompare(b.name) * sortOrder;
                }
                if (sort === '_id' || sort === 'id') {
                    return (a.id - b.id) * sortOrder;
                }
                return 0;
            });
        }
        
        // Pagination
        const { limit, page } = req.query;
        let total = result.length;
        if (limit) {
            const limitNum = parseInt(limit);
            const pageNum = page ? parseInt(page) : 1;
            const start = (pageNum - 1) * limitNum;
            result = result.slice(start, start + limitNum);
        }
        
        res.json({
            products: result,
            total: total,
            page: parseInt(page) || 1,
            pages: limit ? Math.ceil(total / parseInt(limit)) : 1
        });
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

// GET /api/products/:id - Get single product by ID
app.get('/api/products/:id', (req, res) => {
    try {
        const product = products.find(p => p._id === req.params.id || p.id === parseInt(req.params.id));
        
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(product);
    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
});

// GET /api/featured - Get featured products
app.get('/api/featured', (req, res) => {
    try {
        // Return first 8 products as featured
        const featured = products.slice(0, 8);
        res.json(featured);
    } catch (error) {
        console.error('Error fetching featured:', error);
        res.status(500).json({ error: 'Failed to fetch featured products' });
    }
});

// POST /api/cart/:userId/:productId - Add to cart (mock)
app.post('/api/cart/:userId/:productId', (req, res) => {
    try {
        const { userId, productId } = req.params;
        const { quantity } = req.body;
        
        const userIdStr = String(userId);
        
        // Initialize cart if not exists
        if (!carts[userIdStr]) {
            carts[userIdStr] = [];
        }
        
        const product = products.find(p => p._id === productId || p.id === parseInt(productId));
        if (!product) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        // Check if product already in cart
        const existingItem = carts[userIdStr].find(item => 
            String(item.productId) === String(productId)
        );
        
        if (existingItem) {
            existingItem.qty += quantity || 1;
        } else {
            carts[userIdStr].push({
                productId: String(productId),
                name: product.name,
                price: product.price,
                image: product.image,
                qty: quantity || 1
            });
        }
        
        res.json({ 
            success: true, 
            message: 'Product added to cart',
            cart: carts[userIdStr]
        });
    } catch (error) {
        console.error('Error adding to cart:', error);
        res.status(500).json({ error: 'Failed to add to cart' });
    }
});

// GET /api/cart/:userId - Get cart for user
app.get('/api/cart/:userId', (req, res) => {
    try {
        const { userId } = req.params;
        const userIdStr = String(userId);
        
        const cart = carts[userIdStr] || [];
        
        res.json(cart);
    } catch (error) {
        console.error('Error fetching cart:', error);
        res.status(500).json({ error: 'Failed to fetch cart' });
    }
});

// PUT /api/cart/:userId/:productId - Update cart item quantity
app.put('/api/cart/:userId/:productId', (req, res) => {
    try {
        const { userId, productId } = req.params;
        const { quantity } = req.body;
        const userIdStr = String(userId);
        
        if (!carts[userIdStr]) {
            return res.status(404).json({ error: 'Cart not found' });
        }
        
        const item = carts[userIdStr].find(item => 
            String(item.productId) === String(productId)
        );
        
        if (!item) {
            return res.status(404).json({ error: 'Item not found in cart' });
        }
        
        if (quantity <= 0) {
            // Remove item
            carts[userIdStr] = carts[userIdStr].filter(item => 
                String(item.productId) !== String(productId)
            );
        } else {
            item.qty = quantity;
        }
        
        res.json({ 
            success: true, 
            cart: carts[userIdStr]
        });
    } catch (error) {
        console.error('Error updating cart:', error);
        res.status(500).json({ error: 'Failed to update cart' });
    }
});

// DELETE /api/cart/:userId/:productId - Remove item from cart
app.delete('/api/cart/:userId/:productId', (req, res) => {
    try {
        const { userId, productId } = req.params;
        const userIdStr = String(userId);
        
        if (!carts[userIdStr]) {
            return res.status(404).json({ error: 'Cart not found' });
        }
        
        carts[userIdStr] = carts[userIdStr].filter(item => 
            String(item.productId) !== String(productId)
        );
        
        res.json({ 
            success: true, 
            cart: carts[userIdStr]
        });
    } catch (error) {
        console.error('Error removing from cart:', error);
        res.status(500).json({ error: 'Failed to remove from cart' });
    }
});

// DELETE /api/cart/:userId - Clear cart
app.delete('/api/cart/:userId', (req, res) => {
    try {
        const { userId } = req.params;
        const userIdStr = String(userId);
        
        carts[userIdStr] = [];
        
        res.json({ 
            success: true, 
            message: 'Cart cleared',
            cart: []
        });
    } catch (error) {
        console.error('Error clearing cart:', error);
        res.status(500).json({ error: 'Failed to clear cart' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========================================
// AUTHENTICATION ENDPOINTS (In-memory for demo)
// ========================================

// Store users in memory (for demo purposes - users are reset when server restarts)
const users = [];

// POST /api/auth/register - Register a new user
app.post('/api/auth/register', (req, res) => {
    try {
        const { name, email, password, phone } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).json({ error: 'Name, email and password are required' });
        }
        
        // Check if user already exists
        const existingUser = users.find(u => u.email === email);
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }
        
        // Create new user
        const newUser = {
            _id: String(users.length + 1),
            id: users.length + 1,
            name,
            email,
            phone: phone || '',
            password: password, // In production, hash the password!
            createdAt: new Date().toISOString()
        };
        
        users.push(newUser);
        
        // Return user without password
        const { password: _, ...userWithoutPassword } = newUser;
        res.status(201).json({ user: userWithoutPassword, message: 'Registration successful' });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ error: 'Failed to register user' });
    }
});

// POST /api/register - Register (alternative endpoint)
app.post('/api/register', (req, res) => {
    // Forward to /api/auth/register
    req.url = '/api/auth/register';
    app._router.handle(req, res);
});

// POST /api/auth/login - Login user
app.post('/api/auth/login', (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }
        
        // Find user
        const user = users.find(u => u.email === email && u.password === password);
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }
        
        // Return user without password
        const { password: _, ...userWithoutPassword } = user;
        res.json({ user: userWithoutPassword, message: 'Login successful' });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ error: 'Failed to login' });
    }
});

// POST /api/login - Login (alternative endpoint)
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    const user = users.find(u => u.email === email && u.password === password);
    if (!user) {
        return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Return user without password
    const { password: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword, message: 'Login successful' });
});

// GET /api/auth/me - Get current user
app.get('/api/auth/me', (req, res) => {
    try {
        const userId = req.headers['x-user-id'];
        if (!userId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const user = users.find(u => u._id === userId || u.id === parseInt(userId));
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        const { password: _, ...userWithoutPassword } = user;
        res.json(userWithoutPassword);
    } catch (error) {
        console.error('Error getting user:', error);
        res.status(500).json({ error: 'Failed to get user' });
    }
});

// ========================================
// START SERVER
// ========================================
app.listen(PORT, () => {
    console.log(`========================================`);
    console.log(`  Pajay Gadgets - Simple Server`);
    console.log(`  Running on http://localhost:${PORT}`);
    console.log(`========================================`);
    console.log(`  API Endpoints:`);
    console.log(`  - GET    /api/products       - List all products`);
    console.log(`  - GET    /api/products/:id   - Get single product`);
    console.log(`  - GET    /api/featured      - Featured products`);
    console.log(`  - POST   /api/cart/:uid/:pid - Add to cart`);
    console.log(`  - GET    /api/cart/:uid     - Get user cart`);
    console.log(`  - POST   /api/auth/register  - Register user`);
    console.log(`  - POST   /api/auth/login     - Login user`);
    console.log(`  - GET    /api/auth/me       - Get current user`);
    console.log(`========================================`);
});

module.exports = app;
