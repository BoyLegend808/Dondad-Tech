// Admin Panel - Complete Product Management (Phase 3-6)
// Fixed endpoints, auth (cookies), error handling, table rendering, edit/delete

const API_URL = '/api';
let products = [];
let customers = [];
let orders = [];
let editingProductId = null;

document.addEventListener('DOMContentLoaded', () => {
  console.log('[ADMIN] DOM loaded, checking auth...');
  checkAuth();
  updateAdminDropdown();
  
  // Hamburger menu toggle
  const hamburger = document.getElementById('hamburger');
  const dropdownMenu = document.getElementById('dropdown-menu');
  
  if (hamburger && dropdownMenu) {
    hamburger.addEventListener('click', (e) => {
      e.stopPropagation();
      hamburger.classList.toggle('active');
      dropdownMenu.classList.toggle('active');
    });
    
    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (!hamburger.contains(e.target) && !dropdownMenu.contains(e.target)) {
        hamburger.classList.remove('active');
        dropdownMenu.classList.remove('active');
      }
    });
  }
});

// Update admin dropdown with user info
function updateAdminDropdown() {
  const user = JSON.parse(sessionStorage.getItem('dondad_currentUser') || 'null');
  const dropdownUser = document.getElementById('dropdown-user');
  const dropdownLogout = document.getElementById('dropdown-logout');
  const dropdownDivider = document.getElementById('dropdown-divider');
  
  if (user && user.role === 'admin') {
    if (dropdownUser) {
      dropdownUser.textContent = `👤 ${user.name || user.email}`;
      dropdownUser.style.display = 'block';
    }
    if (dropdownLogout) dropdownLogout.style.display = 'block';
    if (dropdownDivider) dropdownDivider.style.display = 'block';
  }
}

// Logout function for hamburger menu
function logout() {
  console.log('[ADMIN] 🚪 Logging out...');
  sessionStorage.removeItem('dondad_currentUser');
  // Call logout API
  fetch('/api/logout', { method: 'POST', credentials: 'include' })
    .then(() => {
      window.location.href = 'index.html';
    })
    .catch(() => {
      window.location.href = 'index.html';
    });
}

async function checkAuth() {
  try {
    // Check stored user
    const storedUser = JSON.parse(sessionStorage.getItem('dondad_currentUser') || 'null');
    if (storedUser && storedUser.role === 'admin') {
      console.log('[ADMIN] Auth OK, loading products');
      document.getElementById('admin-login-section').style.display = 'none';
      document.getElementById('admin-dashboard').style.display = 'block';
      loadProducts();
      return;
    }
    
    // Show login
    document.getElementById('admin-login-section').style.display = 'block';
    document.getElementById('admin-dashboard').style.display = 'none';
    console.log('[ADMIN] No valid session, show login');
  } catch (e) {
    console.error('[ADMIN] Auth check error:', e);
  }
}

// PHASE 4: Fixed loadProducts() - /api/admin/products, credentials:'include', full logging
async function loadProducts() {
  try {
    console.log('[ADMIN] 🔄 Loading products from', API_URL + '/admin/products?page=1&limit=50');
    
    // Fixed: Get the tbody inside #products-table
    const table = document.getElementById('products-table');
    const tbody = table ? table.querySelector('tbody') : null;
    if (!tbody) {
      console.error('[ADMIN] ❌ products-table tbody not found in DOM');
      return;
    }
    
    tbody.innerHTML = `
      <tr>
        <td colspan="6" class="text-center py-4">
          <div class="spinner-border text-primary" role="status">
            <span class="visually-hidden">Loading products...</span>
          </div>
          <p class="mt-2 mb-0">Loading products (0/50)...</p>
        </td>
      </tr>
    `;
    
    const response = await fetch(`${API_URL}/admin/products?page=1&limit=50`, {
      credentials: 'include' // Send cookies for requireAdmin middleware
    });
    
    console.log('[ADMIN] 📡 Response status:', response.status, response.statusText);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    console.log('[ADMIN] 📦 Raw data:', data);
    
    // Handle both {success:true, products:[], pagination:{}} and direct {products:[], pagination:{}}
    products = data.products || data || [];
    console.log('[ADMIN] ✅ Loaded', products.length, 'products');
    
    if (products.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-5">
            <h5 class="text-muted">No products found</h5>
            <p class="text-muted mb-3">Database is empty.</p>
            <button class="btn btn-primary" onclick="seedProducts()">🌱 Seed Sample Products</button>
          </td>
        </tr>
      `;
      return;
    }
    
    renderProductsTable(products, tbody);
    
  } catch (error) {
    console.error('[ADMIN] ❌ loadProducts error:', error);
    
    const tbody = table ? table.querySelector('tbody') : null;
    if (tbody) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="text-center py-5 bg-danger-subtle">
            <h5 class="text-danger mb-2">❌ Failed to load products</h5>
            <p class="text-danger mb-3">${error.message}</p>
            <div class="small text-muted mb-3">
              <strong>Debug:</strong> 
              ${navigator.onLine ? 'Online' : 'Offline'} | 
              Try login → <a href="#" onclick="checkAuth(); return false;">Refresh Auth</a>
            </div>
            <div class="row g-2 justify-content-center">
              <button class="btn btn-outline-primary col-auto" onclick="loadProducts()">🔄 Retry</button>
              <button class="btn btn-secondary col-auto" onclick="testApi()">🧪 Test API</button>
            </div>
          </td>
        </tr>
      `;
    }
  }
}

// PHASE 5: renderProductsTable() - Full table w/ image/name/category/price/stock/buttons
function renderProductsTable(products, tbody) {
  console.log('[ADMIN] 🎨 Rendering', products.length, 'products in table');
  
  tbody.innerHTML = products.map(p => {
    const price = p.price ? `₦${Number(p.price).toLocaleString()}` : 'N/A';
    const stock = p.stock !== undefined ? p.stock : 'N/A';
    const categoryBadge = p.category ? `<span class="badge bg-${getCategoryColor(p.category)}">${p.category}</span>` : 'N/A';
    
    return `
      <tr class="table-row">
        <td class="align-middle">
          <img src="${p.image || 'images/logo.png'}" 
               onerror="this.src='images/logo.png'" 
               class="product-thumb rounded shadow-sm" 
               alt="${p.name}" 
               title="${p.name}">
        </td>
        <td class="align-middle fw-semibold">${p.name || 'Unnamed'}</td>
        <td class="align-middle">${categoryBadge}</td>
        <td class="align-middle fw-bold text-success fs-6">${price}</td>
        <td class="align-middle">
          <span class="badge ${stock > 10 ? 'bg-success' : stock > 0 ? 'bg-warning' : 'bg-danger'}">
            ${stock}
          </span>
        </td>
        <td class="align-middle text-end">
          <div class="btn-group btn-group-sm" role="group">
            <button class="btn btn-outline-primary" onclick="editProduct('${p._id}')" title="Edit">
              <i class="bi bi-pencil"></i>
            </button>
            <button class="btn btn-outline-danger" onclick="deleteProduct('${p._id}')" title="Delete">
              <i class="bi bi-trash"></i>
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');
  
  console.log('[ADMIN] ✅ Table rendered');
}

// Helper for category colors
function getCategoryColor(category) {
  const colors = {
    'phones': 'primary',
    'laptops': 'info', 
    'tablets': 'warning',
    'accessories': 'secondary'
  };
  return colors[category] || 'secondary';
}

// PHASE 6: Fixed editProduct() - PUT /api/admin/products/:id, credentials:'include'
async function editProduct(id) {
  console.log('[ADMIN] ✏️ Edit product:', id);
  const product = products.find(p => p._id === id);
  if (!product) {
    alert('Product not found');
    return;
  }
  
  editingProductId = id;
  document.getElementById('product-id').value = id;
  document.getElementById('product-name').value = product.name || '';
  document.getElementById('product-price').value = product.price || '';
  document.getElementById('product-stock').value = product.stock || '';
  document.getElementById('product-desc').value = product.desc || '';
  document.getElementById('product-category').value = product.category || 'phones';
  document.getElementById('product-full-desc').value = product.fullDesc || '';
  
  // Toggle sections properly
  document.getElementById('admin-dashboard').style.display = 'none';
  document.getElementById('product-form-section').style.display = 'block';
  document.getElementById('form-title').textContent = 'Edit Product';
}

// Fixed deleteProduct()
async function deleteProduct(id) {
  if (!confirm('Delete this product permanently?')) return;
  
  console.log('[ADMIN] 🗑️ Deleting:', id);
  try {
    const response = await fetch(`${API_URL}/admin/products/${id}`, {
      method: 'DELETE',
      credentials: 'include'
    });
    
    if (response.ok) {
      console.log('[ADMIN] ✅ Deleted');
      loadProducts(); // Reload list
    } else {
      const err = await response.json();
      console.error('[ADMIN] ❌ Delete failed:', err);
      alert(`Delete failed: ${err.error || response.statusText}`);
    }
  } catch (e) {
    console.error('[ADMIN] ❌ Delete error:', e);
    alert('Network error');
  }
}

// Fixed form submit - unified create/edit
document.getElementById('product-form')?.addEventListener('submit', async (e) => {
  e.preventDefault();
  console.log('[ADMIN] 💾 Saving product...');
  
  const id = editingProductId;
  const formData = {
    name: document.getElementById('product-name').value.trim(),
    price: parseFloat(document.getElementById('product-price').value) || 0,
    stock: parseInt(document.getElementById('product-stock').value) || 0,
    category: document.getElementById('product-category').value,
    desc: document.getElementById('product-desc').value.trim(),
    fullDesc: document.getElementById('product-full-desc').value.trim()
  };
  
  if (!formData.name || formData.price <= 0) {
    alert('Name and price required');
    return;
  }
  
  try {
    const url = id ? `/admin/products/${id}` : '/admin/products';
    const method = id ? 'PUT' : 'POST';
    
    console.log('[ADMIN] 📤', method, url, formData);
    
    const response = await fetch(`${API_URL}${url}`, {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(formData)
    });
    
    if (response.ok) {
      console.log('[ADMIN] ✅ Saved');
      loadProducts();
      resetForm();
    } else {
      const err = await response.json();
      console.error('[ADMIN] ❌ Save failed:', err);
      alert(`Save failed: ${err.error || response.statusText}`);
    }
  } catch (e) {
    console.error('[ADMIN] ❌ Save error:', e);
    alert('Network error');
  }
});

function resetForm() {
  editingProductId = null;
  document.getElementById('product-form').reset();
  document.getElementById('admin-dashboard').style.display = 'block';
  document.getElementById('product-form-section').style.display = 'none';
}

// Test API endpoint
async function testApi() {
  try {
    console.log('[ADMIN] 🧪 Testing /api/test-products...');
    const response = await fetch('/api/test-products');
    const data = await response.json();
    console.log('[ADMIN] 🧪 Test result:', data);
    alert(`✅ API OK: ${data.count || 0} products found`);
  } catch (e) {
    console.error('[ADMIN] 🧪 Test failed:', e);
    alert('❌ API test failed');
  }
}

// Seed products
async function seedProducts() {
  if (!confirm('Seed ~25 sample products?')) return;
  
  try {
    console.log('[ADMIN] 🌱 Seeding products...');
    await fetch('/api/seed-products');
    setTimeout(loadProducts, 1000);
  } catch (e) {
    console.error('[ADMIN] Seed error:', e);
    alert('Seed failed');
  }
}

// Admin login - use the correct element IDs from admin.html
async function handleAdminLogin(event) {
  if (event) event.preventDefault();
  
  const email = document.getElementById('admin-login-email').value;
  const password = document.getElementById('admin-login-password').value;
  const errorEl = document.getElementById('admin-login-error');
  
  if (!email || !password) {
    if (errorEl) {
      errorEl.textContent = 'Email and password required';
      errorEl.style.display = 'block';
    }
    return;
  }
  
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ email, password })
    });
    
    const data = await response.json();
    if (data.success && data.user && data.user.role === 'admin') {
      sessionStorage.setItem('dondad_currentUser', JSON.stringify(data.user));
      updateAdminDropdown();
      checkAuth();
    } else {
      if (errorEl) {
        errorEl.textContent = data.error || 'Login failed - Admin access required';
        errorEl.style.display = 'block';
      }
    }
  } catch (e) {
    console.error('[ADMIN] Login error:', e);
    if (errorEl) {
      errorEl.textContent = 'Network error - Please try again';
      errorEl.style.display = 'block';
    }
  }
}

// Logout
function adminLogout() {
  sessionStorage.removeItem('dondad_currentUser');
  document.location.reload();
}

// Switch admin tabs (Products, Orders, Customers)
async function switchAdminTab(tabName) {
  console.log('[ADMIN] Switching to tab:', tabName);
  
  // Hide all tab contents
  document.getElementById('products-tab').style.display = 'none';
  document.getElementById('orders-tab').style.display = 'none';
  document.getElementById('customers-tab').style.display = 'none';
  
  // Remove active class from all tabs
  document.querySelectorAll('.admin-tab').forEach(tab => {
    tab.classList.remove('active');
  });
  
  // Show selected tab
  const selectedTab = document.querySelector(`.admin-tab[onclick="switchAdminTab('${tabName}')"]`);
  if (selectedTab) selectedTab.classList.add('active');
  
  // Load data for the selected tab
  if (tabName === 'products') {
    document.getElementById('products-tab').style.display = 'block';
    loadProducts();
  } else if (tabName === 'orders') {
    document.getElementById('orders-tab').style.display = 'block';
    loadOrders();
  } else if (tabName === 'customers') {
    document.getElementById('customers-tab').style.display = 'block';
    loadCustomers();
  }
}

// Load customers from database
async function loadCustomers() {
  try {
    console.log('[ADMIN] 🔄 Loading customers...');
    
    const tbody = document.querySelector('#customers-table');
    if (!tbody) {
      console.error('[ADMIN] ❌ customers-table not found');
      return;
    }
    
    tbody.innerHTML = '<tr><td colspan="6" class="text-center py-4">Loading customers...</td></tr>';
    
    const response = await fetch(`${API_URL}/admin/users?page=1&limit=50`, {
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    customers = data.users || [];
    
    console.log('[ADMIN] ✅ Loaded', customers.length, 'customers');
    
    if (customers.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="text-center py-5">No customers found</td></tr>';
      document.getElementById('no-customers').style.display = 'block';
      return;
    }
    
    document.getElementById('no-customers').style.display = 'none';
    
    // Render customers table
    tbody.innerHTML = customers.map(c => {
      const joinedDate = c.createdAt ? new Date(c.createdAt).toLocaleDateString() : 'N/A';
      return `
        <tr>
          <td class="align-middle">${c.name || 'N/A'}</td>
          <td class="align-middle">${c.email || 'N/A'}</td>
          <td class="align-middle"><span class="badge bg-secondary">${c.role || 'user'}</span></td>
          <td class="align-middle">${joinedDate}</td>
          <td class="align-middle">${c.orderCount || 0}</td>
          <td class="align-middle fw-bold">₦${Number(c.totalSpent || 0).toLocaleString()}</td>
        </tr>
      `;
    }).join('');
    
    // Update stats
    document.getElementById('stat-total-customers').textContent = customers.length;
    
  } catch (error) {
    console.error('[ADMIN] ❌ loadCustomers error:', error);
    const tbody = document.querySelector('#customers-table');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="6" class="text-center py-5 text-danger">Failed to load customers: ${error.message}</td></tr>`;
    }
  }
}

// Load orders from database
async function loadOrders() {
  try {
    console.log('[ADMIN] 🔄 Loading orders...');
    
    const loadingEl = document.getElementById('orders-loading');
    const ordersListEl = document.getElementById('orders-list');
    const noOrdersEl = document.getElementById('no-orders');
    
    if (loadingEl) loadingEl.style.display = 'block';
    if (ordersListEl) ordersListEl.style.display = 'none';
    if (noOrdersEl) noOrdersEl.style.display = 'none';
    
    const response = await fetch(`${API_URL}/admin/orders?page=1&limit=50`, {
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    const data = await response.json();
    orders = data.orders || [];
    
    console.log('[ADMIN] ✅ Loaded', orders.length, 'orders');
    
    if (loadingEl) loadingEl.style.display = 'none';
    
    if (orders.length === 0) {
      if (noOrdersEl) noOrdersEl.style.display = 'block';
      return;
    }
    
    // Render orders list
    if (ordersListEl) {
      ordersListEl.style.display = 'block';
      ordersListEl.innerHTML = orders.map(o => {
        const statusColors = {
          'pending': 'warning',
          'confirmed': 'info',
          'processing': 'primary',
          'shipped': 'info',
          'delivered': 'success',
          'cancelled': 'danger'
        };
        const status = o.status || 'pending';
        const color = statusColors[status] || 'secondary';
        const date = o.createdAt ? new Date(o.createdAt).toLocaleDateString() : 'N/A';
        const total = o.subtotal || o.total || 0;
        
        return `
          <div class="order-card" style="background: var(--card-bg); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; border: 1px solid var(--border);">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 0.5rem;">
              <div>
                <strong>Order #${o._id?.slice(-8) || 'N/A'}</strong>
                <span style="color: var(--text-muted); font-size: 0.9rem; margin-left: 0.5rem;">${date}</span>
              </div>
              <span class="badge bg-${color}">${status}</span>
            </div>
            <div style="margin-top: 0.5rem; display: flex; justify-content: space-between; font-size: 0.9rem;">
              <span>👤 ${o.userId?.name || o.userName || 'Guest'}</span>
              <span class="fw-bold">₦${Number(total).toLocaleString()}</span>
            </div>
          </div>
        `;
      }).join('');
    }
    
    // Update stats
    const pendingCount = orders.filter(o => o.status === 'pending').length;
    document.getElementById('stat-pending-orders').textContent = pendingCount;
    
  } catch (error) {
    console.error('[ADMIN] ❌ loadOrders error:', error);
    const loadingEl = document.getElementById('orders-loading');
    if (loadingEl) {
      loadingEl.innerHTML = `<p class="text-danger">Failed to load orders: ${error.message}</p>`;
    }
  }
}

// Show dashboard (back button from product form)
function showDashboard() {
  document.getElementById('product-form-section').style.display = 'none';
  document.getElementById('admin-dashboard').style.display = 'block';
  loadProducts();
}

// Show add product form
function showAddProduct() {
  editingProductId = null;
  document.getElementById('product-id').value = '';
  document.getElementById('product-form').reset();
  document.getElementById('form-title').textContent = 'Add New Product';
  document.getElementById('admin-dashboard').style.display = 'none';
  document.getElementById('product-form-section').style.display = 'block';
}

