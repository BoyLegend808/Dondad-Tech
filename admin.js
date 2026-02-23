// Admin Panel JavaScript
const API_BASE = '';

// Product state
let adminProducts = [];

// Check if admin is logged in
async function checkAdminAuth() {
    console.log('checkAdminAuth called');
    const accessDenied = document.getElementById('accessDenied');
    const adminContent = document.getElementById('adminContent');
    const body = document.body;

    if (!accessDenied || !adminContent) {
        console.error('Admin elements not found!');
        return;
    }

    // Check localStorage first
    const currentUser = JSON.parse(sessionStorage.getItem('dondad_currentUser') || 'null');
    console.log('Current user from localStorage:', currentUser);
    
    if (currentUser && currentUser.role === 'admin') {
        console.log('Admin logged in, showing admin content');
        accessDenied.style.display = 'none';
        adminContent.style.display = 'block';
        body.style.backgroundColor = 'var(--bg-color)';
        
        // Update nav
        const authLinks = document.getElementById('auth-links');
        const logoutBtn = document.getElementById('logout-btn');
        const userGreeting = document.getElementById('user-greeting');
        
        if (authLinks) authLinks.style.display = 'none';
        if (logoutBtn) logoutBtn.style.display = 'inline-block';
        if (userGreeting) {
            userGreeting.style.display = 'inline';
            userGreeting.textContent = 'Hi, ' + currentUser.name;
        }
        
        await loadProductsFromAPI();
    } else {
        console.log('Not logged in as admin, showing access denied');
        accessDenied.style.display = 'flex';
        adminContent.style.display = 'none';
        // Hide header elements when access denied
        if (authLinks) authLinks.style.display = 'flex';
        if (logoutBtn) logoutBtn.style.display = 'none';
        if (userGreeting) userGreeting.style.display = 'none';
    }
}

// Get auth headers for API requests
function getAuthHeaders() {
    const currentUser = JSON.parse(localStorage.getItem('dondad_currentUser') || sessionStorage.getItem('dondad_currentUser') || 'null');
    if (!currentUser) return {};
    return {
        'Authorization': `Bearer ${currentUser._id}`,
        'X-User-Id': currentUser._id,
        'X-User-Role': currentUser.role || 'user'
    };
}

// Load products from API
async function loadProductsFromAPI() {
    try {
        console.log('Fetching products from API...');
        const response = await fetch(`${API_BASE}/api/products`, {
            headers: getAuthHeaders()
        });
        console.log('Response status:', response.status);
        adminProducts = await response.json();
        console.log('Products loaded:', adminProducts.length, 'products');
        renderAdminProducts();
    } catch (error) {
        console.error('Error loading products:', error);
    }
}

function renderAdminProducts() {
    const tbody = document.getElementById('product-list');
    if (!tbody) {
        console.error('Product list tbody not found!');
        return;
    }
    
    console.log('Rendering', adminProducts.length, 'products');
    
    if (adminProducts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align: center;">No products found. Add your first product!</td></tr>';
        return;
    }

    tbody.innerHTML = adminProducts.map(p => `
        <tr>
            <td><img src="${p.image}" alt="${p.name}"></td>
            <td>${p.name}</td>
            <td>${p.category}</td>
            <td>₦${p.price.toLocaleString()}</td>
            <td>
                <button class="action-btn" onclick="editProduct(${p.id})">Edit</button>
                <button class="action-btn" onclick="deleteProduct(${p.id})">Delete</button>
            </td>
        </tr>
    `).join('');
}

function logoutAdmin() {
    sessionStorage.removeItem('dondad_currentUser');
    localStorage.removeItem('dondad_currentUser');
    window.location.href = 'index.html';
}

// Image preview function
function previewImage(input, previewId) {
    const preview = document.getElementById(previewId);
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            preview.src = e.target.result;
            preview.style.display = 'block';
        };
        reader.readAsDataURL(input.files[0]);
    }
}

let editImageUploaded = false;

function handleEditImageUpload(input) {
    editImageUploaded = true;
    previewImage(input, 'edit-image-preview');
}

function handleAddImageUpload(input) {
    previewImage(input, 'prod-image-preview');
}

function showSection(section) {
    document.getElementById('section-products').style.display = section === 'products' ? 'block' : 'none';
    document.getElementById('section-orders').style.display = section === 'orders' ? 'block' : 'none';
    document.getElementById('section-add').style.display = section === 'add' ? 'block' : 'none';
    document.getElementById('section-edit').style.display = section === 'edit' ? 'block' : 'none';

    document.querySelectorAll('.admin-sidebar li').forEach(li => li.classList.remove('active'));
    if (event && event.target) {
        event.target.classList.add('active');
    }
}

function editProduct(id) {
    editImageUploaded = false;
    const product = adminProducts.find(p => p.id === id);
    if (product) {
        document.getElementById('edit-prod-id').value = product.id;
        document.getElementById('edit-prod-name').value = product.name;
        document.getElementById('edit-prod-category').value = product.category;
        document.getElementById('edit-prod-price').value = product.price;
        document.getElementById('edit-prod-desc').value = product.desc;
        const editPreview = document.getElementById('edit-image-preview');
        if (product.image) {
            editPreview.src = product.image;
            editPreview.style.display = 'block';
        } else {
            editPreview.style.display = 'none';
        }
        showSection('edit');
    }
}

async function deleteProduct(id) {
    if (confirm('Delete this product?')) {
        try {
            const response = await fetch(`${API_BASE}/api/products/${id}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            });

            if (response.ok) {
                await loadProductsFromAPI();
                alert('Product deleted!');
            } else {
                const data = await response.json();
                alert(data.error || 'Failed to delete product');
            }
        } catch (error) {
            console.error('Delete error:', error);
            alert('Connection error');
        }
    }
}

// Add product form
async function handleAddProduct(e) {
    e.preventDefault();

    let image = 'logo.png';
    const imagePreview = document.getElementById('prod-image-preview');
    if (imagePreview.src && imagePreview.style.display !== 'none') {
        image = imagePreview.src;
    }

    const newProduct = {
        name: document.getElementById('prod-name').value,
        category: document.getElementById('prod-category').value,
        price: parseFloat(document.getElementById('prod-price').value),
        desc: document.getElementById('prod-desc').value,
        image: image,
        stock: 10
    };

    try {
        const response = await fetch(`${API_BASE}/api/products`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify(newProduct)
        });

        if (response.ok) {
            await loadProductsFromAPI();
            alert('Product added successfully!');
            document.getElementById('add-product-form').reset();
            document.getElementById('prod-image-preview').style.display = 'none';
            showSection('products');
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to add product');
        }
    } catch (error) {
        console.error('Add product error:', error);
        alert('Connection error');
    }
}

// Edit product form
async function handleEditProduct(e) {
    e.preventDefault();
    const id = document.getElementById('edit-prod-id').value;

    let image = adminProducts.find(p => p._id === id)?.image || 'logo.png';
    const imagePreview = document.getElementById('edit-image-preview');
    if (editImageUploaded && imagePreview.src && imagePreview.style.display !== 'none') {
        image = imagePreview.src;
    }

    const updatedProduct = {
        name: document.getElementById('edit-prod-name').value,
        category: document.getElementById('edit-prod-category').value,
        price: parseFloat(document.getElementById('edit-prod-price').value),
        desc: document.getElementById('edit-prod-desc').value,
        image: image
    };

    try {
        const response = await fetch(`${API_BASE}/api/products/${id}`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                ...getAuthHeaders()
            },
            body: JSON.stringify(updatedProduct)
        });

        if (response.ok) {
            await loadProductsFromAPI();
            alert('Product updated successfully!');
            showSection('products');
            editImageUploaded = false;
        } else {
            const data = await response.json();
            alert(data.error || 'Failed to update product');
        }
    } catch (error) {
        console.error('Update error:', error);
        alert('Connection error');
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Admin page loaded');
    checkAdminAuth();

    // Handle sidebar clicks
    document.querySelectorAll('.admin-sidebar li[data-section]').forEach(li => {
        li.addEventListener('click', function() {
            showSection(this.dataset.section);
        });
    });

    // Handle logout
    const logoutLi = document.getElementById('admin-logout');
    if (logoutLi) {
        logoutLi.addEventListener('click', logoutAdmin);
    }

    // Handle forms
    const addForm = document.getElementById('add-product-form');
    if (addForm) {
        addForm.addEventListener('submit', handleAddProduct);
    }

    const editForm = document.getElementById('edit-product-form');
    if (editForm) {
        editForm.addEventListener('submit', handleEditProduct);
    }
});
