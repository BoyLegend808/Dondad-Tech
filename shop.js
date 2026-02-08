// Shop Page JavaScript
const API_BASE = '';
let allProducts = [];

// Load products from API
async function loadProducts() {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    try {
        const response = await fetch(`${API_BASE}/api/products`);
        allProducts = await response.json();
        renderProducts(allProducts);
    } catch (error) {
        console.error('Error loading products:', error);
        const stored = localStorage.getItem('dondad_products');
        if (stored) {
            allProducts = JSON.parse(stored);
        } else if (typeof products !== 'undefined') {
            allProducts = products;
        } else {
            allProducts = [];
        }
        renderProducts(allProducts);
    }
}

// Render products
function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    grid.innerHTML = products.map(p => `
        <article class="product-card">
            <img src="${p.image}" alt="${p.name}">
            <h3>${p.name}</h3>
            <p class="desc">${p.desc}</p>
            <p class="price">₦${p.price.toLocaleString()}</p>
            <a href="product.html?id=${p.id}" class="btn">View Details</a>
            <button onclick="addToCart(${p.id})" class="btn" style="background-color: var(--accent); margin-top: 0.5rem;">Add to Cart</button>
        </article>
    `).join('');
}

// Filter products by category
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
        if (category === 'all') {
            renderProducts(allProducts);
        } else {
            const filtered = allProducts.filter(p => p.category === category);
            renderProducts(filtered);
        }
    }
}

// Search products
async function searchProducts(term) {
    try {
        const response = await fetch(`${API_BASE}/api/products?search=${encodeURIComponent(term)}`);
        const products = await response.json();
        renderProducts(products);
    } catch (error) {
        const filtered = allProducts.filter(p =>
            p.name.toLowerCase().includes(term) ||
            p.desc.toLowerCase().includes(term)
        );
        renderProducts(filtered);
    }
}

// Add to cart function
function addToCart(productId, qty = 1) {
    const currentUser = JSON.parse(localStorage.getItem('dondad_currentUser'));
    if (!currentUser) {
        alert('Please login to add items to cart. Redirecting to login page...');
        window.location.href = 'login.html';
        return;
    }

    const product = allProducts.find(p => p.id === productId);
    if (!product) return;

    let cart = JSON.parse(localStorage.getItem('cart')) || [];
    const existingItem = cart.find(item => item.id === productId);
    if (existingItem) {
        existingItem.qty += qty;
    } else {
        cart.push({ id: productId, qty: qty });
    }

    localStorage.setItem('cart', JSON.stringify(cart));
    updateCartCount();
    alert(product.name + ' added to cart!');
}

// Initialize on load
document.addEventListener('DOMContentLoaded', function() {
    loadProducts();

    // Category filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', function() {
            filterByCategory(this.dataset.category, this);
        });
    });

    // Search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', function() {
            searchProducts(this.value.toLowerCase());
        });
    }
});
