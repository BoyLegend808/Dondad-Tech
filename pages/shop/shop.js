/* ========================================
   PAJAY GADGETS - SHOP PAGE SCRIPT
   Complete Functionality Implementation
   ======================================== */

const API_BASE = '';
let allProducts = [];
let filteredProducts = [];
let currentView = 'grid';
let currentCategory = 'all';
let currentPage = 1;
const PRODUCTS_PER_PAGE = 12;

// Debounce utility function
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    loadProducts();
    initializeEventListeners();
});

// Initialize all event listeners
function initializeEventListeners() {
    // Search input with debounce
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        const debouncedSearch = debounce((value) => {
            searchProducts(value);
        }, 300);
        
        searchInput.addEventListener('input', (e) => {
            debouncedSearch(e.target.value);
        });
    }
    
    // Category buttons
    const categoryBtns = document.querySelectorAll('.category-btn');
    categoryBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterByCategory(btn.dataset.category, btn);
        });
    });
    
    // View toggle buttons
    const viewBtns = document.querySelectorAll('.view-btn');
    viewBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            toggleView(btn.dataset.view, btn);
        });
    });
}

// Load products from API
async function loadProducts() {
    try {
        const response = await fetch(`${API_BASE}/api/products?limit=500&sort=_id&order=desc`);
        const data = await response.json();
        allProducts = data.products || data;
        filteredProducts = [...allProducts];
        renderProducts();
    } catch (error) {
        console.error('Error loading products:', error);
        // Fallback to localStorage or local products
        if (typeof products !== 'undefined') {
            allProducts = products;
            filteredProducts = [...allProducts];
            renderProducts();
        } else {
            showEmptyState('Failed to load products. Please try again later.');
        }
    }
}

// Filter by category
function filterByCategory(category, btn) {
    currentCategory = category;
    currentPage = 1;
    
    // Update active button
    document.querySelectorAll('.category-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    // Filter products
    if (category === 'all') {
        filteredProducts = [...allProducts];
    } else {
        filteredProducts = allProducts.filter(p => p.category === category);
    }
    
    // Apply search filter if active
    const searchInput = document.getElementById('search-input');
    if (searchInput && searchInput.value.trim()) {
        searchProducts(searchInput.value);
    } else {
        renderProducts();
    }
}

// Search products
function searchProducts(term) {
    currentPage = 1;
    const searchTerm = term.toLowerCase().trim();
    
    // Start with category filter
    let baseProducts = currentCategory === 'all' 
        ? [...allProducts] 
        : allProducts.filter(p => p.category === currentCategory);
    
    if (!searchTerm) {
        filteredProducts = baseProducts;
    } else {
        filteredProducts = baseProducts.filter(p =>
            p.name.toLowerCase().includes(searchTerm) ||
            (p.desc && p.desc.toLowerCase().includes(searchTerm)) ||
            (p.category && p.category.toLowerCase().includes(searchTerm))
        );
    }
    
    renderProducts();
}

// Toggle view (grid/list)
function toggleView(view, btn) {
    currentView = view;
    document.querySelectorAll('.view-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    
    const container = document.getElementById('products-container');
    if (view === 'list') {
        container.classList.add('list-view');
    } else {
        container.classList.remove('list-view');
    }
}

// Render products
function renderProducts() {
    const container = document.getElementById('products-container');
    const resultsCount = document.getElementById('results-count');
    
    if (!container) return;
    
    // Update results count
    if (resultsCount) {
        resultsCount.textContent = filteredProducts.length;
    }
    
    // Check if no products
    if (filteredProducts.length === 0) {
        showEmptyState('No products found. Try adjusting your search or filters.');
        return;
    }
    
    // Paginate products
    const startIndex = (currentPage - 1) * PRODUCTS_PER_PAGE;
    const endIndex = startIndex + PRODUCTS_PER_PAGE;
    const paginatedProducts = filteredProducts.slice(startIndex, endIndex);
    
    // Render product cards
    container.innerHTML = paginatedProducts.map(product => `
        <div class="product-card" onclick="openProductDetails('${product._id || product.id}')">
            <div class="product-image-section">
                <img src="${product.image}" alt="${product.name}" onerror="this.src='../../logo.png'">
                <span class="product-badge">New</span>
                <button class="wishlist-btn" onclick="event.stopPropagation(); toggleWishlist('${product._id || product.id}', this)">
                    <i class="far fa-heart"></i>
                </button>
            </div>
            <div class="product-info">
                <span class="product-category">${product.category || 'Gadget'}</span>
                <h3 class="product-name">${product.name}</h3>
                <p class="product-description">${product.desc || 'Premium quality gadget with advanced features'}</p>
                <div class="product-price">₦${product.price ? product.price.toLocaleString() : 'Contact for price'}</div>
                <div class="product-actions">
                    <button class="btn-add-cart" onclick="event.stopPropagation(); addToCart('${product._id || product.id}')">
                        <i class="fas fa-shopping-cart"></i> Add to Cart
                    </button>
                    <button class="btn-quick-view" onclick="event.stopPropagation(); openProductDetails('${product._id || product.id}')" title="Quick View">
                        <i class="fas fa-eye"></i>
                    </button>
                </div>
            </div>
        </div>
    `).join('');
    
    // Render pagination
    renderPagination();
}

// Show empty state
function showEmptyState(message) {
    const container = document.getElementById('products-container');
    const resultsCount = document.getElementById('results-count');
    
    if (resultsCount) {
        resultsCount.textContent = '0';
    }
    
    if (!container) return;
    
    container.innerHTML = `
        <div class="empty-state">
            <i class="fas fa-search"></i>
            <h3>No Products Found</h3>
            <p>${message}</p>
        </div>
    `;
    
    // Clear pagination
    const paginationContainer = document.getElementById('pagination');
    if (paginationContainer) {
        paginationContainer.innerHTML = '';
    }
}

// Render pagination
function renderPagination() {
    const paginationContainer = document.getElementById('pagination');
    if (!paginationContainer) return;
    
    const totalPages = Math.ceil(filteredProducts.length / PRODUCTS_PER_PAGE);
    
    if (totalPages <= 1) {
        paginationContainer.innerHTML = '';
        return;
    }
    
    let paginationHTML = '';
    
    // Previous button
    paginationHTML += `
        <button class="pagination-btn" 
                onclick="goToPage(${currentPage - 1})" 
                ${currentPage === 1 ? 'disabled' : ''}>
            <i class="fas fa-chevron-left"></i>
        </button>
    `;
    
    // Page numbers with ellipsis
    for (let i = 1; i <= totalPages; i++) {
        // Show first page, last page, current page, and pages around current
        if (i === 1 || i === totalPages || (i >= currentPage - 1 && i <= currentPage + 1)) {
            paginationHTML += `
                <button class="pagination-btn ${i === currentPage ? 'active' : ''}" 
                        onclick="goToPage(${i})">
                    ${i}
                </button>
            `;
        } else if (i === currentPage - 2 || i === currentPage + 2) {
            // Add ellipsis
            paginationHTML += `<span class="pagination-btn ellipsis">...</span>`;
        }
    }
    
    // Next button
    paginationHTML += `
        <button class="pagination-btn" 
                onclick="goToPage(${currentPage + 1})" 
                ${currentPage === totalPages ? 'disabled' : ''}>
            <i class="fas fa-chevron-right"></i>
        </button>
    `;
    
    paginationContainer.innerHTML = paginationHTML;
}

// Go to specific page
function goToPage(page) {
    const totalPages = Math.ceil(filteredProducts.length / PRODUCTS_PER_PAGE);
    
    if (page < 1 || page > totalPages) return;
    
    currentPage = page;
    renderProducts();
    
    // Scroll to top of products
    const container = document.getElementById('products-container');
    if (container) {
        container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
}

// Add to cart
async function addToCart(productId) {
    const product = allProducts.find(p => (p._id || p.id) === productId);
    if (!product) {
        showToast('Product not found', 'error');
        return;
    }
    
    const user = JSON.parse(sessionStorage.getItem('dondad_currentUser'));
    const cartItem = {
        productId: productId,
        name: product.name,
        price: product.price,
        image: product.image,
        qty: 1
    };
    
    try {
        if (user) {
            // Add to server cart
            const userId = user._id || user.id;
            await fetch(`/api/cart/${userId}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ ...cartItem, quantity: 1 })
            });
        }
        
        // Also add to localStorage as backup
        let localCart = JSON.parse(localStorage.getItem('cart')) || [];
        const existingItem = localCart.find(item => item.productId === productId);
        
        if (existingItem) {
            existingItem.qty += 1;
        } else {
            localCart.push(cartItem);
        }
        
        localStorage.setItem('cart', JSON.stringify(localCart));
        
        // Update cart count
        updateCartCountDisplay();
        
        showToast(`${product.name} added to cart!`, 'success');
        
    } catch (error) {
        console.error('Error adding to cart:', error);
        
        // Still add to localStorage
        let localCart = JSON.parse(localStorage.getItem('cart')) || [];
        const existingItem = localCart.find(item => item.productId === productId);
        
        if (existingItem) {
            existingItem.qty += 1;
        } else {
            localCart.push(cartItem);
        }
        
        localStorage.setItem('cart', JSON.stringify(localCart));
        updateCartCountDisplay();
        
        showToast(`${product.name} added to cart!`, 'success');
    }
}

// Update cart count display
function updateCartCountDisplay() {
    const cartCountEl = document.getElementById('cart-count');
    if (!cartCountEl) return;
    
    let count = 0;
    
    // Get from localStorage
    const localCart = JSON.parse(localStorage.getItem('cart')) || [];
    count = localCart.reduce((sum, item) => sum + item.qty, 0);
    
    cartCountEl.textContent = count;
}

// Toggle wishlist
function toggleWishlist(productId, btn) {
    btn.classList.toggle('active');
    
    const icon = btn.querySelector('i');
    if (btn.classList.contains('active')) {
        icon.classList.remove('far');
        icon.classList.add('fas');
        showToast('Added to wishlist!', 'success');
    } else {
        icon.classList.remove('fas');
        icon.classList.add('far');
        showToast('Removed from wishlist', 'info');
    }
    
    // Save to localStorage
    let wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
    
    if (btn.classList.contains('active')) {
        if (!wishlist.includes(productId)) {
            wishlist.push(productId);
        }
    } else {
        wishlist = wishlist.filter(id => id !== productId);
    }
    
    localStorage.setItem('wishlist', JSON.stringify(wishlist));
}

// Open product details
function openProductDetails(productId) {
    window.location.href = `../../product.html?id=${productId}`;
}

// Toast notification system
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    if (!container) return;
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';
    if (type === 'info') icon = 'info-circle';
    
    toast.innerHTML = `
        <i class="fas fa-${icon} toast-icon"></i>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    container.appendChild(toast);
    
    // Auto remove after 4 seconds
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.remove();
            }
        }, 300);
    }, 4000);
}

// Expose functions globally for inline handlers
window.goToPage = goToPage;
window.toggleWishlist = toggleWishlist;
window.addToCart = addToCart;
window.openProductDetails = openProductDetails;
window.searchProducts = searchProducts;
window.filterByCategory = filterByCategory;
window.toggleView = toggleView;
