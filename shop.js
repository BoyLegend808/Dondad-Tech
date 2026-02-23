// Shop Page JavaScript
const API_BASE = '';

// Get current user from sessionStorage first (more secure)
function getCurrentUser() {
    try {
        const sessionUser = sessionStorage.getItem('dondad_currentUser') || sessionStorage.getItem('dondad_currentUser');
        if (sessionUser) return JSON.parse(sessionUser);
        // Fall back to localStorage for backwards compatibility
        const localUser = localStorage.getItem('dondad_currentUser');
        if (localUser) return JSON.parse(localUser);
        return null;
    } catch {
        return null;
    }
}

// Filter products by category (called from HTML)
function filterProducts(category, btn) {
    filterByCategory(category, btn);
}

// Load products from API
async function loadProducts() {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    try {
        const response = await fetch(`${API_BASE}/api/products`);
        const products = await response.json();
        renderProducts(products);
    } catch (error) {
        // Fallback to local products
        const stored = localStorage.getItem('dondad_products');
        if (stored) {
            renderProducts(JSON.parse(stored));
        } else if (typeof products !== 'undefined') {
            renderProducts(products);
        }
    }
}

// Render products
function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    grid.innerHTML = products.map(p => `
        <article class="product-card" onclick="openProductDetails('${p._id || p.id}')">
            <a href="product.html?id=${p._id || p.id}">
                <img src="${p.image}" alt="${p.name}" onerror="this.src='logo.png'">
            </a>
            <div class="product-card-content">
                <a href="product.html?id=${p._id || p.id}">
                    <h3>${p.name}</h3>
                </a>
                <p class="product-card-desc">${p.desc || ''}</p>
                <p class="price">₦${p.price.toLocaleString()}</p>
                <button onclick="event.stopPropagation(); addToCart('${p._id || p.id}')" class="btn">Add to Cart</button>
            </div>
        </article>
    `).join('');
}

function openProductDetails(productId) {
    window.location.href = `product.html?id=${productId}`;
}

// Filter products
async function filterByCategory(category, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    try {
        const url = category === 'all' 
            ? `${API_BASE}/api/products` 
            : `${API_BASE}/api/products?category=${category}`;
        const response = await fetch(url);
        const products = await response.json();
        renderProducts(products);
    } catch (error) {
        const filtered = category === 'all' 
            ? (typeof products !== 'undefined' ? products : [])
            : (typeof products !== 'undefined' ? products.filter(p => p.category === category) : []);
        renderProducts(filtered);
    }
}

// Search products
async function searchProducts(term) {
    try {
        const response = await fetch(`${API_BASE}/api/products?search=${encodeURIComponent(term)}`);
        const products = await response.json();
        renderProducts(products);
    } catch (error) {
        const filtered = (typeof products !== 'undefined' ? products : []).filter(p =>
            p.name.toLowerCase().includes(term) || 
            p.desc.toLowerCase().includes(term)
        );
        renderProducts(filtered);
    }
}

// Add to cart
async function addToCart(productId, qty = 1) {
    const currentUser = getCurrentUser();
    if (!currentUser) {
        alert('Please login to add items to cart');
        window.location.href = 'login.html';
        return;
    }
    
    const userId = currentUser._id || currentUser.id;
    if (!userId) {
        alert('User error. Please login again.');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/api/cart/${userId}/${productId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ qty: qty || 1 })
        });
        
        if (response.ok) {
            updateCartCount();
            alert('Added to cart!');
        } else {
            alert('Failed to add to cart');
        }
    } catch (error) {
        console.error('Add to cart error:', error);
        alert('Error adding to cart');
    }
}

// Update cart count from server
function updateCartCount() {
    const cartCount = document.getElementById('cart-count');
    if (cartCount) {
        const currentUser = getCurrentUser();
        if (!currentUser) {
            cartCount.textContent = '0';
            return;
        }
        const userId = currentUser._id || currentUser.id;
        if (!userId) {
            cartCount.textContent = '0';
            return;
        }
        fetch(`/api/cart/${userId}`)
            .then(r => r.json())
            .then(cart => {
                const total = Array.isArray(cart) ? cart.reduce((sum, item) => sum + item.qty, 0) : 0;
                cartCount.textContent = total;
            })
            .catch(() => {
                cartCount.textContent = '0';
            });
    }
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    loadProducts();
    
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            filterByCategory(this.dataset.category, this);
        });
    });

    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            searchProducts(this.value.toLowerCase());
        });
    }
});
