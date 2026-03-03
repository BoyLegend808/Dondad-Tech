// JavaScript for index/home page
// This file contains page-specific logic for the home page

document.addEventListener('DOMContentLoaded', function() {
    console.log('Index page loaded');
    
    // Fetch featured products
    fetchFeaturedProducts();
    
    // Update cart count
    updateCartCount();
    
    // Check user login status
    checkUserStatus();
});

async function fetchFeaturedProducts() {
    try {
        const response = await fetch('/api/featured');
        const products = await response.json();
        
        const container = document.getElementById('featured-products');
        if (container && products.length > 0) {
            container.innerHTML = products.map(product => `
                <article class="product-card" onclick="window.location.href='../product/product.html?id=${product.id}'">
                    <img src="${product.image}" alt="${product.name}" onerror="this.src='../logo.png'">
                    <div class="product-card-content">
                        <h3>${product.name}</h3>
                        <p class="product-card-desc">${product.desc || ''}</p>
                        <p class="price">₦${product.price.toLocaleString()}</p>
                    </div>
                </article>
            `).join('');
        }
    } catch (error) {
        console.error('Error fetching featured products:', error);
    }
}

function updateCartCount() {
    fetch('/api/cart')
        .then(r => r.ok ? r.json() : [])
        .then(cart => {
            const countEl = document.getElementById('cart-count');
            if (countEl) {
                const total = Array.isArray(cart) ? cart.reduce((sum, item) => sum + item.qty, 0) : 0;
                countEl.textContent = total;
            }
        })
        .catch(console.error);
}

function checkUserStatus() {
    const userStr = sessionStorage.getItem('dondad_currentUser');
    const authButtons = document.getElementById('auth-buttons');
    const userMenu = document.getElementById('user-menu');
    
    if (userStr && authButtons && userMenu) {
        try {
            const user = JSON.parse(userStr);
            authButtons.style.display = 'none';
            userMenu.style.display = 'flex';
            
            const userName = document.getElementById('user-name');
            const userAvatar = document.getElementById('user-avatar');
            
            if (userName) userName.textContent = user.name;
            if (userAvatar) {
                userAvatar.textContent = user.name.split(' ').map(n => n[0]).join('').substring(0, 2);
            }
            
            // Show admin link if admin
            if (user.role === 'admin') {
                const adminNavLink = document.getElementById('admin-nav-link');
                if (adminNavLink) adminNavLink.style.display = 'block';
            }
        } catch (e) {
            console.error('Error parsing user:', e);
        }
    }
}
