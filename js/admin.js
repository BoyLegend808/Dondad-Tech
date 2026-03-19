// Simple Admin JS - Products List + Edit
const API_URL = '/api';
let products = [];

document.addEventListener('DOMContentLoaded', () => {
  checkAuth();
  loadProducts();
});

async function checkAuth() {
  const user = JSON.parse(sessionStorage.getItem('dondad_currentUser') || 'null');
  if (!user || user.role !== 'admin') {
    document.getElementById('admin-login-section').style.display = 'block';
    document.getElementById('admin-dashboard').style.display = 'none';
  }
}

async function loadProducts() {
  try {
    const tbody = document.getElementById('products-table');
    tbody.innerHTML = '<tr><td colspan="5">Loading...</td></tr>';
    
    const response = await fetch(API_URL + '/products?page=1&limit=50');
    const data = await response.json();
    products = data.products || [];
    
    if (products.length === 0) {
      tbody.innerHTML = '<tr><td colspan="5">No products. <button onclick="seedProducts()">Seed Sample Products</button></td></tr>';
      return;
    }
    
    tbody.innerHTML = products.map(p => `
      <tr>
        <td><img src="${p.image}" onerror="this.src='images/logo.png'" class="product-thumb"></td>
        <td>${p.name}</td>
        <td><span class="category-badge">${p.category}</span></td>
        <td>₦${p.price.toLocaleString()}</td>
        <td>
          <button onclick="editProduct('${p._id}')" class="btn btn-edit">Edit</button>
          <button onclick="deleteProduct('${p._id}')" class="btn btn-delete">Delete</button>
        </td>
      </tr>
    `).join('');
  } catch (e) {
    document.getElementById('products-table').innerHTML = '<tr><td colspan="5">Error loading products</td></tr>';
  }
}

async function seedProducts() {
  try {
    await fetch(API_URL + '/seed-products');
    loadProducts();
  } catch (e) {
    alert('Seed error');
  }
}

function editProduct(id) {
  const product = products.find(p => p._id === id);
  if (!product) return;
  
  document.getElementById('product-id').value = id;
  document.getElementById('product-name').value = product.name;
  document.getElementById('product-price').value = product.price;
  document.getElementById('product-stock').value = product.stock || 10;
  document.getElementById('product-desc').value = product.desc || '';
  document.getElementById('product-category').value = product.category || 'phones';
  
  document.getElementById('admin-dashboard').style.display = 'none';
  document.getElementById('product-form-section').style.display = 'block';
}

async function deleteProduct(id) {
  if (!confirm('Delete?')) return;
  try {
    await fetch(API_URL + '/products/' + id, { method: 'DELETE' });
    loadProducts();
  } catch (e) {
    alert('Delete error');
  }
}

document.getElementById('product-form').onsubmit = async (e) => {
  e.preventDefault();
  const id = document.getElementById('product-id').value;
  const formData = {
    name: document.getElementById('product-name').value,
    price: parseFloat(document.getElementById('product-price').value),
    stock: parseInt(document.getElementById('product-stock').value),
    category: document.getElementById('product-category').value,
    desc: document.getElementById('product-desc').value
  };
  
  try {
    const url = id ? `/products/${id}` : '/products';
    const method = id ? 'PUT' : 'POST';
    await fetch(API_URL + url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formData)
    });
    loadProducts();
    document.getElementById('admin-dashboard').style.display = 'block';
    document.getElementById('product-form-section').style.display = 'none';
  } catch (e) {
    alert('Save error');
  }
};

