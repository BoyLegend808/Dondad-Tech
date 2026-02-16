// Shop Page JavaScript
const API_BASE = '';

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
        <article class="product-card">
            <a href="product.html?id=${p._id || p.id}">
                <img src="${p.image}" alt="${p.name}" onerror="this.src='logo.png'">
            </a>
            <div class="product-card-content">
                <a href="product.html?id=${p._id || p.id}">
                    <h3>${p.name}</h3>
                </a>
                <p class="product-card-desc">${p.desc || ''}</p>
                <p class="price">₦${p.price.toLocaleString()}</p>
                <button onclick="addToCart('${p._id || p.id}')" class="btn">Add to Cart</button>
            </div>
        </article>
    `).join('');
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
function addToCart(productId, qty = 1) {
    const currentUser = JSON.parse(sessionStorage.getItem('dondad_currentUser'));
    console.log('Current user from sessionStorage:', currentUser);
    if (!currentUser) {
        alert('Please login to add items to cart');
        window.location.href = 'login.html';
        return;
    }
    
    let cart = JSON.parse(localStorage.getItem('cart')) || [];
    const existingItem = cart.find(item => item.id === productId || item._id === productId);
    if (existingItem) {
        existingItem.qty += qty;
    } else {
        cart.push({ _id: productId, qty: qty });
    }
    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartCount();
    alert('Added to cart!');
}

// Update cart count
function updateCartCount() {
    const cartCount = document.getElementById('cart-count');
    if (cartCount) {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        const total = cart.reduce((sum, item) => sum + item.qty, 0);
        cartCount.textContent = total;
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
