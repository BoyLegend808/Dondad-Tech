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

// Current pagination state
let currentPage = 1;
let currentCategory = '';
let currentSearch = '';

// Load products from API with pagination
async function loadProducts(page = 1) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    currentPage = page;
    
    try {
        let url = `${API_BASE}/api/products?page=${page}&limit=20`;
        if (currentCategory && currentCategory !== 'all') {
            url += `&category=${currentCategory}`;
        }
        if (currentSearch) {
            url += `&search=${encodeURIComponent(currentSearch)}`;
        }
        
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.products) {
            renderProducts(data.products);
            renderPagination(data.pagination);
        } else {
            // Handle legacy format (array directly)
            renderProducts(data);
        }
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

// Render pagination controls
function renderPagination(pagination) {
    let paginationContainer = document.getElementById('pagination');
    if (!paginationContainer) {
        // Create pagination container if it doesn't exist
        paginationContainer = document.createElement('div');
        paginationContainer.id = 'pagination';
        paginationContainer.className = 'pagination';
        const grid = document.getElementById('product-grid');
        if (grid && grid.parentNode) {
            grid.parentNode.appendChild(paginationContainer);
        }
    }
    
    if (!pagination || pagination.pages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }
    
    let html = '';
    
    // Previous button
    if (pagination.hasPrev) {
        html += `<button onclick="loadProducts(${pagination.page - 1})" class="btn pagination-btn">Previous</button>`;
    }
    
    // Page numbers
    for (let i = 1; i <= pagination.pages; i++) {
        if (i === pagination.page) {
            html += `<span class="pagination-current">${i}</span>`;
        } else if (i === 1 || i === pagination.pages || (i >= pagination.page - 2 && i <= pagination.page + 2)) {
            html += `<button onclick="loadProducts(${i})" class="btn pagination-btn">${i}</button>`;
        } else if (i === pagination.page - 3 || i === pagination.page + 3) {
            html += `<span class="pagination-ellipsis">...</span>`;
        }
    }
    
    // Next button
    if (pagination.hasNext) {
        html += `<button onclick="loadProducts(${pagination.page + 1})" class="btn pagination-btn">Next</button>`;
    }
    
    paginationContainer.innerHTML = html;
}

// Render products
function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    grid.innerHTML = products.map(p => `
        <article class="product-card" onclick="openProductDetails('${p._id || p.id}')">
            <a href="pages/product/product.html?id=${p._id || p.id}">
                <img src="${p.image}" alt="${p.name}" onerror="this.src='logo.png'">
            </a>
            <div class="product-card-content">
                <a href="pages/product/product.html?id=${p._id || p.id}">
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
    window.location.href = `pages/product/product.html?id=${productId}`;
}

// Filter products
async function filterByCategory(category, btn) {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    currentCategory = category;
    currentPage = 1;
    
    try {
        let url = `${API_BASE}/api/products?page=1&limit=20`;
        if (category && category !== 'all') {
            url += `&category=${category}`;
        }
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.products) {
            renderProducts(data.products);
            renderPagination(data.pagination);
        } else {
            renderProducts(data);
        }
    } catch (error) {
        console.error('Filter error:', error);
    }
}

// Search products
async function searchProducts(term) {
    currentSearch = term;
    currentPage = 1;
    
    try {
        const url = `${API_BASE}/api/products?page=1&limit=20&search=${encodeURIComponent(term)}`;
        const response = await fetch(url);
        const data = await response.json();
        
        if (data.products) {
            renderProducts(data.products);
            renderPagination(data.pagination);
        } else {
            renderProducts(data);
        }
    } catch (error) {
        console.error('Search error:', error);
    }
}

// Advanced search with autocomplete
let searchTimeout = null;
async function handleSearchInput(term) {
    if (searchTimeout) clearTimeout(searchTimeout);
    
    if (!term || term.length < 2) {
        document.getElementById('search-results')?.remove();
        return;
    }
    
    searchTimeout = setTimeout(async () => {
        try {
            const response = await fetch(`${API_BASE}/api/search/autocomplete?q=${encodeURIComponent(term)}`);
            const data = await response.json();
            showSearchSuggestions(data.suggestions || []);
        } catch (error) {
            console.error('Autocomplete error:', error);
        }
    }, 300);
}

function showSearchSuggestions(suggestions) {
    let container = document.getElementById('search-results');
    if (!container) {
        container = document.createElement('div');
        container.id = 'search-results';
        container.className = 'search-results';
        
        const searchInput = document.querySelector('.search-input') || document.querySelector('#search');
        if (searchInput) {
            searchInput.parentElement.appendChild(container);
        }
    }
    
    if (suggestions.length === 0) {
        container.innerHTML = '<div class="search-no-results">No products found</div>';
        return;
    }
    
    container.innerHTML = suggestions.map(p => `
        <div class="search-suggestion" onclick="selectSearchSuggestion('${p.name}', '${p._id || p.id}')">
            <img src="${p.image}" alt="${p.name}" onerror="this.src='logo.png'">
            <div class="search-suggestion-info">
                <div class="search-suggestion-name">${p.name}</div>
                <div class="search-suggestion-category">${p.category}</div>
            </div>
            <div class="search-suggestion-price">₦${p.price.toLocaleString()}</div>
        </div>
    `).join('');
}

function selectSearchSuggestion(name, productId) {
    document.getElementById('search-results')?.remove();
    window.location.href = `pages/product/product.html?id=${productId}`;
}

// Hide search results when clicking outside
document.addEventListener('click', (e) => {
    if (!e.target.closest('.search-container')) {
        document.getElementById('search-results')?.remove();
    }
});

// Add to cart
async function addToCart(productId, qty = 1) {
    const currentUser = getCurrentUser();
    if (!currentUser) {
        alert('Please login to add items to cart');
        window.location.href = 'pages/login/login.html';
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
        fetch(`/api/cart/${userId}`, {
            credentials: "include"
        })
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
    // Check if there's a category parameter in the URL
    const urlParams = new URLSearchParams(window.location.search);
    const categoryParam = urlParams.get('category');
    
    if (categoryParam) {
        // Find the filter button for this category
        const filterBtn = document.querySelector(`.filter-btn[data-category="${categoryParam}"]`);
        if (filterBtn) {
            // Remove active from all buttons and add to this one
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            filterBtn.classList.add('active');
            filterByCategory(categoryParam, filterBtn);
        } else {
            // No matching button found, just load all products
            console.log('Category not found in filter buttons:', categoryParam);
            loadProducts();
        }
    } else {
        loadProducts();
    }
    
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
