// Admin Panel - Complete Product Management (Phase 3-6)
// Fixed endpoints, auth (cookies), error handling, table rendering, edit/delete

const API_URL = '/api';
let products = [];
let editingProductId = null;

document.addEventListener('DOMContentLoaded', () => {
  console.log('[ADMIN] DOM loaded, checking auth...');
  checkAuth();
});

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
    
    const tbody = document.getElementById('products-table-body') || document.querySelector('#products-table tbody');
    if (!tbody) {
      console.error('[ADMIN] ❌ products-table or tbody not found in DOM');
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
    
    const tbody = document.querySelector('#products-table tbody');
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
  
  // Toggle sections
  document.querySelector('.admin-main')?.classList.add('d-none');
  document.getElementById('product-form-section').classList.remove('d-none');
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
  document.querySelector('.admin-main')?.classList.remove('d-none');
  document.getElementById('product-form-section')?.classList.add('d-none');
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

// Admin login (existing, cookies handled by server)
async function handleAdminLogin() {
  const email = document.getElementById('admin-email').value;
  const password = document.getElementById('admin-password').value;
  
  if (!email || !password) {
    alert('Email/password required');
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
    if (data.success && data.user.role === 'admin') {
      sessionStorage.setItem('dondad_currentUser', JSON.stringify(data.user));
      checkAuth();
    } else {
      alert(data.error || 'Login failed');
    }
  } catch (e) {
    alert('Login error');
  }
}

// Logout
function adminLogout() {
  sessionStorage.removeItem('dondad_currentUser');
  document.location.reload();
}

