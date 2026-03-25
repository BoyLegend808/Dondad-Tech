/** 
 * DONDAD Admin App Logic
 * Modularized, clean, and robust for a better developer/user experience.
 */

// Global State
let products = [];
let orders = [];
let customers = [];
let activeTab = 'dashboard';
let isEditing = false;

// --- Initialization ---

document.addEventListener('DOMContentLoaded', () => {
    checkAuth();
    setupNavigation();
    setupForms();
    setupDragAndDrop();
    setupVariantToggles();
});

// Auth check logic
function checkAuth() {
    const userString = sessionStorage.getItem('dondad_currentUser') || localStorage.getItem('dondad_currentUser');
    if (!userString) {
        showLogin();
        return;
    }

    try {
        const user = JSON.parse(userString);
        if (user.role !== 'admin') {
            showToast('Admin access required', 'error');
            showLogin();
            return;
        }

        // Successfully logged in
        document.getElementById('admin-name').textContent = user.name || 'Administrator';
        const initials = (user.name || 'AD').split(' ').map(n=>n[0]).join('').substring(0,2).toUpperCase();
        const avatarEl = document.getElementById('admin-avatar');
        if (avatarEl) avatarEl.textContent = initials;
        
        showDashboard();
        refreshAllData();
    } catch (e) {
        showLogin();
    }
}

function showLogin() {
    document.getElementById('login-section').style.display = 'flex';
    document.getElementById('dashboard-layout').style.display = 'none';
    document.getElementById('product-modal').style.display = 'none';
}

function handleUnauthorized() {
    console.warn('Unauthorized request. Redirecting to login.');
    sessionStorage.removeItem('dondad_currentUser');
    showLogin();
    showToast('Session expired. Please sign in again.', 'error');
}

function showDashboard() {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('dashboard-layout').style.display = 'flex';
    switchTab('dashboard');
}

function handleLogout() {
    sessionStorage.removeItem('dondad_currentUser');
    localStorage.removeItem('dondad_currentUser');
    fetch(`${API_BASE}/logout`, { method: 'POST', credentials: 'include' }).finally(() => {
        window.location.href = 'index.html';
    });
}

// --- Navigation ---

function setupNavigation() {
    // Debounce guard to prevent double-fire from touch + click on Android
    let lastAction = 0;
    function debounceGuard() {
        const now = Date.now();
        if (now - lastAction < 300) return false;
        lastAction = now;
        return true;
    }

    // Tab navigation buttons
    const navItems = document.querySelectorAll('.nav-item[data-tab]');
    navItems.forEach(item => {
        const handler = (e) => {
            e.preventDefault();
            if (!debounceGuard()) return;
            const tab = item.getAttribute('data-tab');
            switchTab(tab);
        };
        item.addEventListener('click', handler);
        item.addEventListener('touchend', handler);
    });

    // Mobile hamburger menu button
    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    if (mobileMenuBtn) {
        const menuHandler = (e) => {
            e.preventDefault();
            e.stopPropagation();
            if (!debounceGuard()) return;
            toggleSidebar();
        };
        mobileMenuBtn.addEventListener('click', menuHandler);
        mobileMenuBtn.addEventListener('touchend', menuHandler);
    }

    // Sidebar overlay (tap to close, but not when clicking sidebar itself)
    const overlay = document.getElementById('sidebar-overlay');
    const sidebar = document.getElementById('sidebar');
    if (overlay) {
        const overlayHandler = (e) => {
            e.preventDefault();
            // Only close if clicking directly on overlay, not on sidebar
            if (e.target === overlay && !debounceGuard()) return;
            if (e.target === overlay) {
                closeSidebar();
            }
        };
        overlay.addEventListener('click', overlayHandler);
        overlay.addEventListener('touchend', overlayHandler);
    }
    
    // Ensure sidebar is fully visible by forcing a reflow after adding active class
    if (sidebar) {
        const observer = new MutationObserver(() => {
            if (sidebar.classList.contains('active')) {
                // Force reflow to ensure transition works properly
                void sidebar.offsetHeight;
            }
        });
        observer.observe(sidebar, { attributes: true, attributeFilter: ['class'] });
    }
}

function switchTab(tab) {
    activeTab = tab;
    
    // UI Update
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    const activeNav = document.querySelector(`.nav-item[data-tab="${tab}"]`);
    if (activeNav) activeNav.classList.add('active');
    
    document.querySelectorAll('.tab-content').forEach(c => c.style.display = 'none');
    const tabEl = document.getElementById(`tab-${tab}`);
    if (tabEl) tabEl.style.display = 'block';

    // Refresh data if needed
    if (tab === 'dashboard') refreshAllData();
    if (tab === 'products') loadProducts();
    if (tab === 'orders') loadOrders();
    if (tab === 'customers') loadCustomers();

    // Close sidebar on mobile after clicking
    if (window.innerWidth <= 1024) {
        closeSidebar();
    }
}

function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    const isActive = sidebar.classList.contains('active');
    if (isActive) {
        closeSidebar();
    } else {
        sidebar.classList.add('active');
        if (overlay) overlay.classList.add('active');
        // Prevent body scroll when sidebar is open
        document.body.style.overflow = 'hidden';
    }
}

function closeSidebar() {
    const sidebar = document.getElementById('sidebar');
    const overlay = document.getElementById('sidebar-overlay');
    sidebar.classList.remove('active');
    if (overlay) overlay.classList.remove('active');
    document.body.style.overflow = '';
}

// --- API Calls ---

async function refreshAllData() {
    await Promise.all([
        loadDashboardStats(),
        loadRecentOrders(),
        loadRecentProducts()
    ]);
}

async function loadDashboardStats() {
    try {
        const res = await fetch(`${API_BASE}/admin/dashboard`, { credentials: 'include' });
        if (!res.ok) return;
        const data = await res.json();
        
        // Update Stats
        document.getElementById('stat-revenue').textContent = `₦${Number(data.totalRevenue || 0).toLocaleString()}`;
        document.getElementById('stat-orders').textContent = data.pendingOrders || 0;
        document.getElementById('stat-stock').textContent = data.lowStockCount || 0;
        document.getElementById('stat-customers').textContent = data.totalUsers || 0;
        
        document.getElementById('last-updated').textContent = `Last update: ${new Date().toLocaleTimeString()}`;
    } catch (e) {
        console.error('Stats loading failed:', e);
    }
}

async function loadProducts() {
    const list = document.getElementById('products-list');
    const empty = document.getElementById('products-empty');
    if (!list) return;

    list.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 2rem;">Loading products...</td></tr>';

    try {
        const res = await fetch(`${API_BASE}/admin/products?limit=100`, { credentials: 'include' });
        
        if (res.status === 401) {
            handleUnauthorized();
            return;
        }

        if (!res.ok) throw new Error(`Status ${res.status}`);
        
        const data = await res.json();
        products = data.products || [];

        if (products.length === 0) {
            list.innerHTML = '';
            empty.style.display = 'block';
            return;
        }

        empty.style.display = 'none';
        list.innerHTML = products.map(p => `
            <tr>
                <td><img src="${p.image || 'images/logo.png'}" style="width: 48px; height: 48px; object-fit: cover; border-radius: 8px;"></td>
                <td>
                    <div style="font-weight: 500;">${p.name}</div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">${p._id?.slice(-8)}</div>
                </td>
                <td><span class="badge" style="background: rgba(255,255,255,0.1);">${p.category}</span></td>
                <td style="font-weight: 600;">₦${Number(p.price || 0).toLocaleString()}</td>
                <td>
                    <span class="badge ${p.stock < 5 ? 'badge-danger' : 'badge-success'}">${p.stock}</span>
                </td>
                <td style="text-align: right;">
                    <div style="display: flex; gap: 0.5rem; justify-content: flex-end;">
                        <button class="btn btn-secondary" onclick="editProduct('${p._id}')"><i class="fas fa-edit"></i></button>
                        <button class="btn btn-danger" onclick="deleteProduct('${p._id}')"><i class="fas fa-trash"></i></button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        list.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--error);">Failed to load products.</td></tr>';
    }
}

async function loadRecentOrders() {
    const list = document.getElementById('recent-orders-list');
    if (!list) return;

    try {
        const res = await fetch(`${API_BASE}/admin/orders?limit=5`, { credentials: 'include' });
        const data = await res.json();
        const recent = data.orders || [];

        list.innerHTML = recent.length ? recent.map(o => `
            <tr>
                <td><strong>#${o._id?.slice(-8)}</strong></td>
                <td>${o.userName || 'Guest'}</td>
                <td>${new Date(o.createdAt).toLocaleDateString()}</td>
                <td style="font-weight: 600;">₦${Number(o.subtotal || 0).toLocaleString()}</td>
                <td><span class="badge badge-${o.status === 'delivered' ? 'success' : 'warning'}">${o.status}</span></td>
            </tr>
        `).join('') : '<tr><td colspan="5">No recent orders.</td></tr>';
    } catch (e) {
        list.innerHTML = '<tr><td colspan="5">Failed to load recent orders.</td></tr>';
    }
}

async function loadRecentProducts() {
    const list = document.getElementById('recent-products-list');
    if (!list) return;

    try {
        const res = await fetch(`${API_BASE}/admin/products?limit=5&sort=createdAt&order=desc`, { credentials: 'include' });
        const data = await res.json();
        const recent = data.products || [];

        list.innerHTML = recent.length ? recent.map(p => `
            <tr>
                <td><strong>${p.name}</strong></td>
                <td>₦${Number(p.price || 0).toLocaleString()}</td>
                <td><span class="badge ${p.stock < 10 ? 'badge-warning' : 'badge-success'}">${p.stock}</span></td>
                <td><span class="badge" style="background:rgba(255,255,255,0.05);">${p.category}</span></td>
            </tr>
        `).join('') : '<tr><td colspan="4">No products yet.</td></tr>';
    } catch (e) {
        list.innerHTML = '<tr><td colspan="4">Failed to load recent products.</td></tr>';
    }
}

async function loadOrders() {
    const list = document.getElementById('full-orders-list');
    if (!list) return;

    list.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 2rem;">Loading history...</td></tr>';

    try {
        const res = await fetch(`${API_BASE}/admin/orders?limit=50`, { credentials: 'include' });
        const data = await res.json();
        orders = data.orders || [];

        list.innerHTML = orders.map(o => `
            <tr>
                <td><strong>#${o._id?.slice(-8)}</strong></td>
                <td>
                    <div style="font-weight: 500;">${o.userName}</div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">${o.userEmail}</div>
                </td>
                <td>${new Date(o.createdAt).toLocaleString()}</td>
                <td style="font-weight: 600;">₦${Number(o.subtotal || 0).toLocaleString()}</td>
                <td>
                    <select onchange="updateOrderStatus('${o._id}', this.value)" style="padding: 2px 4px; font-size: 0.75rem; width: auto;">
                        <option value="pending" ${o.status === 'pending' ? 'selected' : ''}>Pending</option>
                        <option value="confirmed" ${o.status === 'confirmed' ? 'selected' : ''}>Confirmed</option>
                        <option value="processing" ${o.status === 'processing' ? 'selected' : ''}>Processing</option>
                        <option value="shipped" ${o.status === 'shipped' ? 'selected' : ''}>Shipped</option>
                        <option value="delivered" ${o.status === 'delivered' ? 'selected' : ''}>Delivered</option>
                        <option value="cancelled" ${o.status === 'cancelled' ? 'selected' : ''}>Cancelled</option>
                    </select>
                </td>
                <td style="text-align: right;">
                    <button class="btn btn-secondary" onclick="viewOrderDetails('${o._id}')"><i class="fas fa-eye"></i></button>
                </td>
            </tr>
        `).join('');
    } catch (e) {
        list.innerHTML = '<tr><td colspan="6" style="text-align:center; color: var(--error);">Failed to load orders.</td></tr>';
    }
}

async function loadCustomers() {
     const list = document.getElementById('customers-list-tbody');
    if (!list) return;

    list.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 2rem;">Loading customer records...</td></tr>';

    try {
        console.log('Fetching customers...');
        const res = await fetch(`${API_BASE}/admin/users?limit=100`, { credentials: 'include' });
        
        if (res.status === 401) {
            handleUnauthorized();
            return;
        }

        if (!res.ok) throw new Error(`Status ${res.status}`);
        const data = await res.json();
        customers = data.users || data || [];

        if (!customers.length) {
            list.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 3rem; color: var(--text-muted);">No customer accounts found.</td></tr>';
            return;
        }

        list.innerHTML = customers.map(c => `
            <tr>
                <td>
                    <div style="font-weight: 700;">${c.name || c.email?.split('@')[0] || 'Unknown User'}</div>
                    <span class="badge" style="font-size: 0.65rem; background: ${c.role === 'admin' ? 'rgba(59,130,246,0.2)' : 'rgba(255,255,255,0.05)'}; color: ${c.role === 'admin' ? 'var(--primary)' : 'var(--text-muted)'};">
                        ${(c.role || 'user').toUpperCase()}
                    </span>
                </td>
                <td>${c.email || 'N/A'}</td>
                <td>${c.createdAt ? new Date(c.createdAt).toLocaleDateString() : 'N/A'}</td>
                <td>${c.orderCount || 0}</td>
                <td style="font-weight: 600;">₦${Number(c.totalSpent || 0).toLocaleString()}</td>
            </tr>
        `).join('');
    } catch (e) {
        console.error('Customer fetch failed:', e);
        list.innerHTML = `<tr><td colspan="5" style="text-align:center; color: var(--error);">Error: ${e.message}</td></tr>`;
    }
}

// --- Login Handler ---
const adminLoginForm = document.getElementById('admin-login-form') || document.getElementById('login-form');
if (adminLoginForm) {
    adminLoginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    const errorEl = document.getElementById('login-error');
    
    errorEl.style.display = 'none';

    try {
        const res = await fetch(`${API_BASE}/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });
        const data = await res.json();

        if (res.ok && data.success && data.user.role === 'admin') {
            sessionStorage.setItem('dondad_currentUser', JSON.stringify(data.user));
            localStorage.setItem('dondad_currentUser', JSON.stringify(data.user));
            showToast('Welcome back, Admin!', 'success');
            checkAuth();
        } else {
            errorEl.textContent = data.error || 'Access denied. Admins only.';
            errorEl.style.display = 'block';
        }
    } catch (e) {
        errorEl.textContent = 'Server connection failed.';
        errorEl.style.display = 'block';
    }
});
}

// --- Product Management ---

function setupForms() {
    document.getElementById('product-form').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const saveBtn = document.getElementById('save-btn');
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';

        const id = document.getElementById('edit-id').value;
        const payload = {
            name: document.getElementById('p-name').value,
            category: document.getElementById('p-category').value,
            price: Number(document.getElementById('p-price').value),
            stock: Number(document.getElementById('p-stock').value),
            desc: document.getElementById('p-desc').value,
            fullDesc: document.getElementById('p-fulldesc').value,
            image: document.getElementById('p-image-base64').value,
            hasVariants: document.getElementById('has-variants').checked,
            variants: getVariantsFromForm()
        };

        try {
            const url = id ? `${API_BASE}/admin/products/${id}` : `${API_BASE}/admin/products`;
            const method = id ? 'PUT' : 'POST';

            const res = await fetch(url, {
                method,
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                showToast(`Product ${id ? 'updated' : 'created'} successfully!`, 'success');
                hideProductForm();
                loadProducts();
                refreshAllData();
            } else {
                const data = await res.json();
                showToast(data.error || 'Failed to save product', 'error');
            }
        } catch (e) {
            showToast('Network error while saving', 'error');
        } finally {
            saveBtn.disabled = false;
            saveBtn.innerHTML = 'Save Product';
        }
    });
}

function showProductForm() {
    isEditing = false;
    document.getElementById('product-form').reset();
    document.getElementById('edit-id').value = '';
    document.getElementById('modal-title').textContent = 'Create New Product';
    document.getElementById('p-image-preview').style.display = 'none';
    document.getElementById('p-image-base64').value = '';
    prefillVariants(null);
    document.getElementById('product-modal').style.display = 'block';
}

async function editProduct(id) {
    const p = products.find(prod => prod._id === id);
    if (!p) return;

    isEditing = true;
    document.getElementById('modal-title').textContent = 'Edit Product';
    document.getElementById('edit-id').value = p._id;
    document.getElementById('p-name').value = p.name || '';
    document.getElementById('p-category').value = p.category || 'phones';
    document.getElementById('p-price').value = p.price || 0;
    document.getElementById('p-stock').value = p.stock || 0;
    document.getElementById('p-desc').value = p.desc || '';
    document.getElementById('p-fulldesc').value = p.fullDesc || '';
    
    prefillVariants(p.variants);

    if (p.image) {
        const preview = document.getElementById('p-image-preview');
        preview.src = p.image;
        preview.style.display = 'block';
        document.getElementById('p-image-base64').value = p.image;
    }

    document.getElementById('product-modal').style.display = 'block';
}

function hideProductForm() {
    document.getElementById('product-modal').style.display = 'none';
}

// --- Variant Management ---

function setupVariantToggles() {
    const hasVariants = document.getElementById('has-variants');
    const editor = document.getElementById('variants-editor');
    if (hasVariants && editor) {
        hasVariants.addEventListener('change', () => {
            editor.style.display = hasVariants.checked ? 'block' : 'none';
        });
    }
}

function addVariant(type, data = {}) {
    const container = document.getElementById(`${type}-container`);
    if (!container) return;

    const row = document.createElement('div');
    row.className = `variant-row ${type}-row`;
    row.style = 'display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 0.5rem; align-items: start;';
    
    const option = data.option || '';
    const priceMod = data.priceModifier || 0;
    const stock = data.stock || 0;

    row.innerHTML = `
        <div class="form-group" style="margin-bottom:0;"><input type="text" class="v-opt" placeholder="Option (e.g. 256GB)" value="${option}" required></div>
        <div class="form-group" style="margin-bottom:0;"><input type="number" class="v-price" placeholder="+ Price" value="${priceMod}"></div>
        <div class="form-group" style="margin-bottom:0;"><input type="number" class="v-stock" placeholder="Stock" value="${stock}"></div>
        <button type="button" class="btn btn-danger btn-sm" onclick="this.parentElement.remove()" style="padding: 0.5rem;"><i class="fas fa-trash"></i></button>
    `;

    container.appendChild(row);
}

function getVariantsFromForm() {
    const hasVariants = document.getElementById('has-variants').checked;
    if (!hasVariants) return null;

    const getRows = (type) => [...document.querySelectorAll(`.${type}-row`)].map(row => ({
        option: row.querySelector('.v-opt').value.trim(),
        priceModifier: Number(row.querySelector('.v-price').value) || 0,
        stock: Number(row.querySelector('.v-stock').value) || 0
    })).filter(v => v.option);

    return {
        storage: getRows('storage'),
        ram: getRows('ram'),
        color: getRows('color')
    };
}

function prefillVariants(variantsData) {
    const hasVariants = document.getElementById('has-variants');
    const editor = document.getElementById('variants-editor');
    
    // Reset
    document.getElementById('storage-container').innerHTML = '';
    document.getElementById('ram-container').innerHTML = '';
    document.getElementById('color-container').innerHTML = '';

    if (variantsData && (variantsData.storage?.length || variantsData.ram?.length || variantsData.color?.length)) {
        hasVariants.checked = true;
        editor.style.display = 'block';
        
        if (variantsData.storage) variantsData.storage.forEach(v => addVariant('storage', v));
        if (variantsData.ram) variantsData.ram.forEach(v => addVariant('ram', v));
        if (variantsData.color) variantsData.color.forEach(v => addVariant('color', v));
    } else {
        hasVariants.checked = false;
        editor.style.display = 'none';
    }
}

async function deleteProduct(id) {
    if (!confirm('Are you sure you want to delete this product? This action cannot be undone.')) return;

    try {
        const res = await fetch(`${API_BASE}/admin/products/${id}`, {
            method: 'DELETE',
            credentials: 'include'
        });

        if (res.ok) {
            showToast('Product removed correctly', 'success');
            loadProducts();
            refreshAllData();
        } else {
            showToast('Failed to delete product', 'error');
        }
    } catch (e) {
        showToast('Network error', 'error');
    }
}

async function updateOrderStatus(orderId, status) {
    try {
        const res = await fetch(`${API_BASE}/admin/orders/${orderId}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'include',
            body: JSON.stringify({ status })
        });
        if (res.ok) {
            showToast('Order status updated', 'success');
            loadDashboardStats();
        } else {
            showToast('Failed to update status', 'error');
        }
    } catch (e) {
        showToast('Network error', 'error');
    }
}

// --- Image Handling ---

function setupDragAndDrop() {
    const zone = document.getElementById('image-drop-zone');
    const input = document.getElementById('p-image-input');

    zone.addEventListener('click', () => input.click());

    input.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (file) handleFile(file);
    });

    zone.addEventListener('dragover', (e) => {
        e.preventDefault();
        zone.style.borderColor = 'var(--primary)';
    });

    zone.addEventListener('dragleave', () => {
        zone.style.borderColor = 'var(--border)';
    });

    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        zone.style.borderColor = 'var(--border)';
        const file = e.dataTransfer.files[0];
        if (file) handleFile(file);
    });
}

function handleFile(file) {
    if (!file.type.startsWith('image/')) {
        showToast('Invalid file type. Please upload an image.', 'error');
        return;
    }

    const reader = new FileReader();
    reader.onload = (e) => {
        const preview = document.getElementById('p-image-preview');
        preview.src = e.target.result;
        preview.style.display = 'block';
        document.getElementById('p-image-base64').value = e.target.result;
    };
    reader.readAsDataURL(file);
}

// --- Utilities ---

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.style.borderLeft = `4px solid ${type === 'success' ? 'var(--success)' : 'var(--error)'}`;
    toast.innerHTML = `
        <div style="display:flex; align-items:center; gap:0.5rem;">
            <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-circle'}"></i>
            <span>${message}</span>
        </div>
    `;
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateY(20px)';
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// --- Order Details ---
function viewOrderDetails(orderId) {
    const order = orders.find(o => o._id === orderId);
    if (!order) {
        showToast('Order not found', 'error');
        return;
    }

    const items = (order.items || []).map(i =>
        `<div style="display:flex;justify-content:space-between;padding:0.5rem 0;border-bottom:1px solid var(--border);">
            <span>${i.name || 'Item'} x${i.qty || 1}</span>
            <span>₦${Number(i.price || 0).toLocaleString()}</span>
        </div>`
    ).join('') || '<p class="text-muted">No item details available.</p>';

    const modal = document.getElementById('product-modal');
    modal.innerHTML = `
        <div class="card" style="max-width:600px;margin:0 auto;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:1.5rem;">
                <h2>Order #${orderId.slice(-8)}</h2>
                <button class="btn btn-secondary" id="close-order-detail" type="button"><i class="fas fa-times"></i></button>
            </div>
            <div style="margin-bottom:1rem;">
                <p><strong>Customer:</strong> ${order.userName || 'Guest'}</p>
                <p><strong>Email:</strong> ${order.userEmail || 'N/A'}</p>
                <p><strong>Date:</strong> ${new Date(order.createdAt).toLocaleString()}</p>
                <p><strong>Status:</strong> <span class="badge badge-${order.status === 'delivered' ? 'success' : 'warning'}">${order.status}</span></p>
            </div>
            <h3 style="margin-bottom:0.75rem;">Items</h3>
            ${items}
            <div style="text-align:right;margin-top:1rem;font-size:1.25rem;font-weight:700;">
                Total: ₦${Number(order.subtotal || 0).toLocaleString()}
            </div>
        </div>
    `;
    modal.style.display = 'block';
    document.getElementById('close-order-detail').addEventListener('click', () => {
        modal.style.display = 'none';
        // Restore the original product form modal content on next use
    });
}
