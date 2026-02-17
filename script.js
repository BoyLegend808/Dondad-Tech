// Pajay Gadgets - Main JavaScript

// Cart functionality
let cart = JSON.parse(localStorage.getItem("cart")) || [];

// User authentication
const USERS_KEY = "dondad_users";
const CURRENT_USER_KEY = "dondad_currentUser";

// Session configuration for auto-logout
const SESSION_TIMEOUT = 15 * 60 * 1000; // 15 minutes of inactivity
let sessionTimer = null;
let isOffline = false;
let offlineTimer = null;

// Reset session timer on user activity
function resetSessionTimer() {
    if (sessionTimer) {
        clearTimeout(sessionTimer);
    }
    const currentUser = getCurrentUser();
    if (currentUser) {
        sessionTimer = setTimeout(() => {
            logoutUser('Session expired due to inactivity. Please login again.');
        }, SESSION_TIMEOUT);
    }
}

// Handle offline detection
function handleOffline() {
    isOffline = true;
    offlineTimer = setTimeout(() => {
        const currentUser = getCurrentUser();
        if (currentUser) {
            logoutUser('You have been logged out due to being offline for too long.');
        }
    }, 60000); // 60 seconds offline = logout
}

// Handle online detection
function handleOnline() {
    isOffline = false;
    if (offlineTimer) {
        clearTimeout(offlineTimer);
        offlineTimer = null;
    }
    resetSessionTimer();
}

// Handle tab close - logout immediately
function handleTabClose() {
    const currentUser = getCurrentUser();
    if (currentUser) {
        sessionStorage.removeItem(CURRENT_USER_KEY);
    }
}

// Setup auto-logout listeners
function setupAutoLogout() {
    const currentUser = getCurrentUser();
    if (currentUser) {
        resetSessionTimer();
        
        // Listen for user activity to reset timer
        ['mousedown', 'keydown', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetSessionTimer, { passive: true });
        });
    }
    
    // Listen for online/offline status
    window.addEventListener('offline', handleOffline);
    window.addEventListener('online', handleOnline);
    
    // Handle tab close
    window.addEventListener('beforeunload', handleTabClose);
    
    // Handle visibility change (mobile)
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            handleTabClose();
        }
    });
}

// Product persistence key
const PRODUCTS_KEY = "dondad_products";

// Load products from localStorage or use default from products.js
function getAllProducts() {
  const stored = localStorage.getItem(PRODUCTS_KEY);
  if (stored) {
    return JSON.parse(stored);
  }
  return products; // Fallback to products.js
}

// Get products by category
function getProductsByCategory(category) {
  const allProducts = getAllProducts();
  if (category === "all") return allProducts;
  return allProducts.filter((p) => p.category === category);
}

// Get product by ID (supports both numeric id and MongoDB _id)
function getProductById(id) {
  const allProducts = getAllProducts();
  return allProducts.find((p) => p.id === parseInt(id) || p._id === id);
}

// Search products
function searchProducts(query) {
  const allProducts = getAllProducts();
  const term = query.toLowerCase();
  return allProducts.filter(
    (p) =>
      p.name.toLowerCase().includes(term) ||
      p.desc.toLowerCase().includes(term),
  );
}

// Initialize default user accounts
function initializeDefaultAccounts() {
  let users = getUsers();

  // Ensure users array exists
  if (!Array.isArray(users)) {
    users = [];
  }

  // Check if customer account already exists
  const customerExists = users.find(
    (u) => u.email === "ugwunekejohn5@gmail.com",
  );

  if (!customerExists) {
    // Add customer account
    users.push({
      name: "John",
      email: "ugwunekejohn5@gmail.com",
      phone: "08012345678",
      password: "customer123",
      role: "customer",
    });
    setUsers(users);
    console.log(
      "Customer account created: ugwunekejohn5@gmail.com / customer123",
    );
  }

  // Check if admin account already exists
  const adminExists = users.find((u) => u.email === "admin@dondadtech.com");

  if (!adminExists) {
    // Add admin account
    users.push({
      name: "Admin",
      email: "admin@dondadtech.com",
      phone: "08000000000",
      password: "admin123",
      role: "admin",
    });
    setUsers(users);
    console.log("Admin account created: admin@dondadtech.com / admin123");
  }
}

// Initialize on load
initializeDefaultAccounts();

// Debug: Clear all user data (call resetUsers() in console to reset)
window.resetUsers = function () {
  localStorage.removeItem(USERS_KEY);
  localStorage.removeItem(CURRENT_USER_KEY);
  initializeDefaultAccounts();
  console.log("Users reset! Default accounts recreated.");
  alert(
    "User data reset! Refresh the page to login.\n\nCustomer: ugwunekejohn5@gmail.com / customer123\nAdmin: admin@dondadtech.com / admin123",
  );
  location.reload();
};

// Force logout and refresh (call forceLogout() in console)
window.forceLogout = function () {
  localStorage.removeItem(CURRENT_USER_KEY);
  console.log("Forced logout! Refreshing...");
  location.reload();
};

// Clear user session on page load (for testing)
window.clearUserSession = function () {
  localStorage.removeItem(CURRENT_USER_KEY);
  console.log("User session cleared!");
  updateAuthUI();
};

// Auto-clear user session on page load (uncomment to always start logged out)
// localStorage.removeItem(CURRENT_USER_KEY);

function getUsers() {
  return JSON.parse(localStorage.getItem(USERS_KEY)) || [];
}

function setUsers(users) {
  localStorage.setItem(USERS_KEY, JSON.stringify(users));
}

function getCurrentUser() {
  return JSON.parse(sessionStorage.getItem(CURRENT_USER_KEY));
}

function setCurrentUser(user) {
  sessionStorage.setItem(CURRENT_USER_KEY, JSON.stringify(user));
}

function logoutUser(message = null) {
  sessionStorage.removeItem(CURRENT_USER_KEY);
  updateAuthUI();
  if (message) {
    alert(message);
  } else {
    alert("You have been logged out successfully!");
  }
  window.location.href = "index.html";
}

function isLoggedIn() {
  return getCurrentUser() !== null;
}

function loginUser(email, password) {
  const users = getUsers();
  const user = users.find((u) => u.email === email && u.password === password);
  if (user) {
    setCurrentUser({
      name: user.name,
      email: user.email,
      phone: user.phone,
      role: user.role,
    });
    return true;
  }
  return false;
}

function isAdmin() {
  const user = getCurrentUser();
  return user && user.role === "admin";
}

function registerUser(name, email, phone, password) {
  const users = getUsers();
  if (users.find((u) => u.email === email)) {
    return { success: false, message: "Email already registered" };
  }
  users.push({ name, email, phone, password });
  setUsers(users);
  setCurrentUser({ name, email, phone });
  return { success: true };
}

function updateAuthUI() {
  const authLinks = document.getElementById("auth-links");
  const userGreeting = document.getElementById("user-greeting");
  const logoutBtn = document.getElementById("logout-btn");
  const userMenu = document.getElementById("user-menu");
  const userName = document.getElementById("user-name");
  const userAvatar = document.getElementById("user-avatar");
  const user = getCurrentUser();

  if (authLinks) {
    if (user) {
      authLinks.style.display = "none";

      // Handle enhanced user menu
      if (userMenu && userName && userAvatar) {
        userMenu.style.display = "flex";
        const initials = user.name
          .split(" ")
          .map((n) => n[0])
          .join("")
          .substring(0, 2);
        userAvatar.textContent = initials || user.name.charAt(0);
        userName.textContent = user.name;
      }

      // Legacy support
      if (userGreeting) {
        userGreeting.style.display = "inline";
        userGreeting.textContent = `Hi, ${user.name}`;
      }
      if (logoutBtn) {
        logoutBtn.style.display = "inline-block";
      }
    } else {
      authLinks.style.display = "flex";
      if (userMenu) userMenu.style.display = "none";
      if (userGreeting) {
        userGreeting.style.display = "none";
      }
      if (logoutBtn) {
        logoutBtn.style.display = "none";
      }
    }
  }
}

function addToCart(productId, qty = 1) {
  // Require login before adding to cart
  if (!isLoggedIn()) {
    alert("Please login to add items to cart. Redirecting to login page...");
    window.location.href = "login.html";
    return;
  }

  const product = getProductById(productId);
  if (!product) return;

  const existingItem = cart.find(
    (item) => item._id === productId || item.id === productId,
  );
  if (existingItem) {
    existingItem.qty += qty;
  } else {
    cart.push({ _id: productId, qty: qty });
  }
  saveCart();
  alert(product.name + " added to cart!");
}

function saveCart() {
  localStorage.setItem("cart", JSON.stringify(cart));
  updateCartCount();
}

function updateCartCount() {
  const cartCount = document.getElementById("cart-count");
  if (cartCount) {
    const currentUser = JSON.parse(sessionStorage.getItem('dondad_currentUser'));
    if (!currentUser) {
      cartCount.textContent = '0';
      return;
    }
    const userId = currentUser._id || currentUser.id;
    if (!userId) {
      cartCount.textContent = '0';
      return;
    }
    fetch(`/api/cart/${userId}`)
      .then(r => r.json())
      .then(cart => {
        let totalItems = 0;
        if (Array.isArray(cart) && cart.length > 0) {
          totalItems = cart.reduce((sum, item) => sum + item.qty, 0);
        } else {
          const localCart = JSON.parse(localStorage.getItem("cart")) || [];
          totalItems = localCart.reduce((sum, item) => sum + item.qty, 0);
        }
        cartCount.textContent = totalItems;
      })
      .catch(() => {
        const localCart = JSON.parse(localStorage.getItem("cart")) || [];
        const totalItems = localCart.reduce((sum, item) => sum + item.qty, 0);
        cartCount.textContent = totalItems;
      });
  }
}

function removeFromCart(productId) {
  cart = cart.filter((item) => item._id !== productId && item.id !== productId);
  saveCart();
  renderCart();
}

function updateCartQty(productId, qty) {
  const item = cart.find(
    (item) => item._id === productId || item.id === productId,
  );
  if (item) {
    item.qty = qty;
    if (item.qty <= 0) {
      removeFromCart(productId);
    } else {
      saveCart();
      renderCart();
    }
  }
}

function getCartItems() {
  return cart.map((item) => {
    const product = getProductById(item._id || item.id);
    return { ...product, qty: item.qty };
  });
}

function getCartTotal() {
  return cart.reduce((sum, item) => {
    const product = getProductById(item._id || item.id);
    return sum + (product ? product.price * item.qty : 0);
  }, 0);
}

// Render functions
function renderProducts(products, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return;

  container.innerHTML = products
    .map(
      (product) => `
        <div class="product-card" onclick="window.location.href='product.html?id=${product.id}'">
            <img src="${product.image}" alt="${product.name}">
            <h3>${product.name}</h3>
            <p>${product.desc}</p>
            <p class="price">₦${product.price.toLocaleString()}</p>
            <button class="add-btn" onclick="event.stopPropagation(); addToCart(${product.id})">Add to Cart</button>
        </div>
    `,
    )
    .join("");
}

function renderCart() {
  const cartItems = getCartItems();
  const container = document.getElementById("cart-items");
  const totalEl = document.getElementById("cart-total");

  if (!container) return;

  if (cartItems.length === 0) {
    container.innerHTML =
      '<p style="text-align: center; padding: 2rem;">Your cart is empty</p>';
    if (totalEl) totalEl.textContent = "₦0";
    return;
  }

  container.innerHTML = cartItems
    .map(
      (item) => `
        <div class="cart-item">
            <img src="${item.image}" alt="${item.name}">
            <div class="cart-item-info">
                <h3>${item.name}</h3>
                <p>₦${item.price.toLocaleString()}</p>
            </div>
            <div class="cart-item-qty">
                <button onclick="updateCartQty(${item.id}, ${item.qty - 1})">-</button>
                <span>${item.qty}</span>
                <button onclick="updateCartQty(${item.id}, ${item.qty + 1})">+</button>
            </div>
            <button class="cart-item-remove" onclick="removeFromCart(${item.id})">×</button>
        </div>
    `,
    )
    .join("");

  if (totalEl) totalEl.textContent = "₦" + getCartTotal().toLocaleString();
}

// Search function
function setupSearch() {
  const searchInput = document.getElementById("searchInput");
  if (!searchInput) return;

  searchInput.addEventListener("keyup", (e) => {
    const term = e.target.value.toLowerCase();
    const filtered = searchProducts(term);
    renderProducts(filtered, "product-grid");
  });
}

// Category filter
function setupCategoryFilter() {
  const filterBtns = document.querySelectorAll(".filter-btn");
  filterBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      filterBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const category = btn.dataset.category;
      const filtered = getProductsByCategory(category);
      renderProducts(filtered, "product-grid");
    });
  });
}

// Hamburger menu
function setupHamburger() {
  const hamburger = document.querySelector(".hamburger");
  const navLinks = document.querySelector(".nav-links");
  console.log("Hamburger setup - hamburger:", hamburger);
  console.log("Hamburger setup - navLinks:", navLinks);

  if (hamburger && navLinks) {
    // Toggle menu function
    const toggleMenu = function (e) {
      e.preventDefault();
      e.stopPropagation();
      console.log("Hamburger clicked!");
      hamburger.classList.toggle("active");
      navLinks.classList.toggle("active");
      console.log("Hamburger classes:", hamburger.classList);
      console.log("NavLinks classes:", navLinks.classList);
    };

    // Support both click and touch events for mobile
    hamburger.addEventListener("click", toggleMenu);
    hamburger.addEventListener("touchstart", toggleMenu, { passive: false });

    // Close menu when clicking outside
    document.addEventListener("click", (e) => {
      if (
        navLinks.classList.contains("active") &&
        !navLinks.contains(e.target) &&
        !hamburger.contains(e.target)
      ) {
        hamburger.classList.remove("active");
        navLinks.classList.remove("active");
      }
    });

    navLinks.querySelectorAll("a").forEach((link) => {
      link.addEventListener("click", () => {
        hamburger.classList.remove("active");
        navLinks.classList.remove("active");
      });
    });
  } else {
    console.error("Hamburger or navLinks not found!");
  }
}

// Initialize
document.addEventListener("DOMContentLoaded", () => {
  updateCartCount();
  setupHamburger();
  updateAuthUI();
  setupAutoLogout();

  // Homepage featured products
  const allProducts = getAllProducts();
  renderProducts(allProducts.slice(0, 8), "featured-products");

  // Shop page
  const productGrid = document.getElementById("product-grid");
  if (productGrid) {
    const urlParams = new URLSearchParams(window.location.search);
    const category = urlParams.get("category") || "all";
    renderProducts(getProductsByCategory(category), "product-grid");
    setupSearch();
    setupCategoryFilter();
  }

  // Cart page
  renderCart();

  // Checkout page
  const checkoutForm = document.getElementById("checkout-form");
  if (checkoutForm) {
    checkoutForm.addEventListener("submit", (e) => {
      e.preventDefault();
      alert("Order placed successfully! We will contact you shortly.");
      cart = [];
      saveCart();
      window.location.href = "index.html";
    });
  }

  // Login page
  const loginForm = document.getElementById("login-form");
  if (loginForm) {
    loginForm.addEventListener("submit", (e) => {
      e.preventDefault();
      e.stopPropagation();
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;
      console.log("Login attempt for:", email);

      if (loginUser(email, password)) {
        const user = getCurrentUser();
        console.log("Login successful for:", user.email);
        if (user.role === "admin") {
          alert("Admin login successful! Redirecting to admin panel...");
          window.location.href = "admin.html";
        } else {
          alert("Login successful! Welcome back, " + user.name);
          window.location.href = "index.html";
        }
      } else {
        console.log("Login failed for:", email);
        // Debug: Show current users in console
        const users = getUsers();
        console.log("Current users in database:", users);
        alert(
          "Invalid email or password! If you're using the default account, try registering a new account or type 'resetUsers()' in the browser console to reset.",
        );
      }
      return false;
    });
  }

  // Register page
  const registerForm = document.getElementById("register-form");
  if (registerForm) {
    registerForm.addEventListener("submit", (e) => {
      e.preventDefault();
      const name = document.getElementById("name").value;
      const email = document.getElementById("email").value;
      const phone = document.getElementById("phone").value;
      const password = document.getElementById("password").value;
      const confirm = document.getElementById("confirm").value;

      if (password !== confirm) {
        alert("Passwords do not match!");
        return;
      }

      const result = registerUser(name, email, phone, password);
      if (result.success) {
        alert("Registration successful! Welcome, " + name);
        window.location.href = "index.html";
      } else {
        alert(result.message);
      }
    });
  }
});
// View local database (call viewDatabase() in console)
window.viewDatabase = function () {
  console.log("=== LOCAL DATABASE ===");
  console.log(
    "Users:",
    JSON.parse(localStorage.getItem("dondad_users") || "[]"),
  );
  console.log(
    "Current User:",
    JSON.parse(localStorage.getItem("dondad_currentUser") || "null"),
  );
  console.log(
    "Products:",
    JSON.parse(localStorage.getItem("dondad_products") || "[]"),
  );
  console.log("Cart:", JSON.parse(localStorage.getItem("cart") || "[]"));
  alert("Local database logged to console! Press F12 to view.");
};
