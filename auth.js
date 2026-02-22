// Authentication JavaScript
const API_BASE = '';

// Session configuration
const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours - session persists across tab closes
const SESSION_KEY = 'pajay_session_valid';
const SESSION_TIMESTAMP_KEY = 'pajay_session_timestamp';
let sessionTimer = null;
let isOffline = false;
let offlineTimer = null;

// Check and validate session on page load
function validateSession() {
    const sessionValid = localStorage.getItem(SESSION_KEY);
    const sessionTimestamp = localStorage.getItem(SESSION_TIMESTAMP_KEY);
    
    if (sessionValid && sessionTimestamp) {
        const now = Date.now();
        const elapsed = now - parseInt(sessionTimestamp);
        
        // If session has expired (more than 24 hours since last activity), logout
        if (elapsed > SESSION_TIMEOUT) {
            clearSession();
            return false;
        }
        
        return true;
    }
    return false;
}

// Clear session completely
function clearSession() {
    localStorage.removeItem(SESSION_KEY);
    localStorage.removeItem(SESSION_TIMESTAMP_KEY);
    localStorage.removeItem('dondad_currentUser');
}

// Mark session as valid and track timestamp
function markSessionValid() {
    localStorage.setItem(SESSION_KEY, 'true');
    localStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
}

// Update last activity timestamp
function updateLastActivity() {
    localStorage.setItem('pajay_last_activity', Date.now().toString());
}

// Reset session timer on user activity
function resetSessionTimer() {
    if (sessionTimer) {
        clearTimeout(sessionTimer);
    }
    const currentUser = JSON.parse(localStorage.getItem('dondad_currentUser'));
    if (currentUser) {
        sessionTimer = setTimeout(() => {
            logoutUser('Session expired due to inactivity. Please login again.');
        }, SESSION_TIMEOUT);
        // Update timestamp
        localStorage.setItem(SESSION_TIMESTAMP_KEY, Date.now().toString());
    }
}

// Handle offline detection
function handleOffline() {
    isOffline = true;
    // Start a timer when going offline
    offlineTimer = setTimeout(() => {
        const currentUser = JSON.parse(localStorage.getItem('dondad_currentUser'));
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
    // Reset session timer when back online
    resetSessionTimer();
}

// Handle tab close - persist session (no longer clear on tab close)
function handleTabClose() {
    // Session now persists across tab closes - no action needed
}

// Hamburger menu setup
function setupHamburger() {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    if (hamburger && navLinks) {
        hamburger.addEventListener('click', function(e) {
            e.preventDefault();
            e.stopPropagation();
            hamburger.classList.toggle('active');
            navLinks.classList.toggle('active');
        });

        // Close menu when clicking on a link
        navLinks.querySelectorAll('a').forEach(link => {
            link.addEventListener('click', () => {
                hamburger.classList.remove('active');
                navLinks.classList.remove('active');
            });
        });

        // Close menu when clicking outside
        document.addEventListener('click', (e) => {
            if (navLinks.classList.contains('active') && 
                !navLinks.contains(e.target) && 
                !hamburger.contains(e.target)) {
                hamburger.classList.remove('active');
                navLinks.classList.remove('active');
            }
        });
    }
}

// Update navigation based on auth state
function updateAuthNav() {
    const currentUser = JSON.parse(localStorage.getItem('dondad_currentUser'));
    const authLinks = document.getElementById('auth-links');
    const logoutBtn = document.getElementById('logout-btn');
    const userGreeting = document.getElementById('user-greeting');
    const cartLink = document.getElementById('cart-link');
    const adminLink = document.getElementById('admin-link');

    if (currentUser && currentUser.role === 'admin') {
        authLinks.style.display = 'none';
        logoutBtn.style.display = 'inline-block';
        userGreeting.style.display = 'inline';
        userGreeting.textContent = 'Hi, ' + currentUser.name;
        if (cartLink) cartLink.style.display = 'flex';
        if (adminLink) adminLink.style.display = 'block';
        
        // Mark session as valid and start timer
        markSessionValid();
        resetSessionTimer();
    } else if (currentUser) {
        authLinks.style.display = 'none';
        logoutBtn.style.display = 'inline-block';
        userGreeting.style.display = 'inline';
        userGreeting.textContent = 'Hi, ' + currentUser.name;
        if (cartLink) cartLink.style.display = 'flex';
        if (adminLink) adminLink.style.display = 'none';
        
        // Mark session as valid and start timer
        markSessionValid();
        resetSessionTimer();
    } else {
        authLinks.style.display = 'flex';
        logoutBtn.style.display = 'none';
        userGreeting.style.display = 'none';
        if (cartLink) cartLink.style.display = 'none';
        if (adminLink) adminLink.style.display = 'none';
        
        // Clear session timer for logged out user
        if (sessionTimer) {
            clearTimeout(sessionTimer);
            sessionTimer = null;
        }
    }
}

// Single logout function
function logoutUser(message = null) {
    clearSession();
    window.location.href = 'index.html';
}

// Update cart count
function updateCartCount() {
    const cartCount = document.getElementById('cart-count');
    if (cartCount) {
        let cart = JSON.parse(localStorage.getItem('cart')) || [];
        const totalItems = cart.reduce((sum, item) => sum + item.qty, 0);
        cartCount.textContent = totalItems;
    }
}

// Initialize common functionality
function initCommon() {
    setupHamburger();
    updateAuthNav();
    updateCartCount();

    // Handle logout buttons (both ID and class based)
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', function(e) {
            e.preventDefault();
            logoutUser();
        });
    }
    
    // Also handle logout links with onclick
    const logoutLinks = document.querySelectorAll('.logout-btn');
    logoutLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            logoutUser();
        });
    });

    // Listen for online/offline status
    window.addEventListener('offline', handleOffline);
    window.addEventListener('online', handleOnline);

    // Handle tab close - immediately clear session
    window.addEventListener('beforeunload', handleTabClose);
    
    // Also handle visibility change (more reliable for mobile)
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'hidden') {
            handleTabClose();
        }
    });
}

// Login function
async function handleLogin(e) {
    e.preventDefault();

    const errorEl = document.getElementById('login-error');
    errorEl.classList.remove('visible');

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch(`${API_BASE}/api/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('dondad_currentUser', JSON.stringify(data.user));
            if (data.user.role === 'admin') {
                window.location.href = 'admin.html';
            } else {
                window.location.href = 'index.html';
            }
        } else {
            errorEl.textContent = data.error || 'Invalid credentials';
            errorEl.classList.add('visible');
        }
    } catch (error) {
        console.error('Login error:', error);
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.classList.add('visible');
    }
}

// Register function
async function handleRegister(e) {
    e.preventDefault();

    const errorEl = document.getElementById('register-error');
    errorEl.classList.remove('visible');

    const name = document.getElementById('name').value;
    const email = document.getElementById('email').value;
    const phone = document.getElementById('phone').value;
    const password = document.getElementById('password').value;
    const confirm = document.getElementById('confirm').value;

    if (password !== confirm) {
        errorEl.textContent = 'Passwords do not match. Please try again.';
        errorEl.classList.add('visible');
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/api/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, phone })
        });

        const data = await response.json();

        if (response.ok) {
            window.location.href = 'login.html';
        } else {
            errorEl.textContent = data.error || 'Registration failed. Please try again.';
            errorEl.classList.add('visible');
        }
    } catch (error) {
        console.error('Registration error:', error);
        errorEl.textContent = 'Connection error. Please try again.';
        errorEl.classList.add('visible');
    }
}

// Initialize on load
document.addEventListener('DOMContentLoaded', function() {
    initCommon();

    const loginForm = document.getElementById('login-form');
    if (loginForm) {
        loginForm.addEventListener('submit', handleLogin);
    }

    const registerForm = document.getElementById('register-form');
    if (registerForm) {
        registerForm.addEventListener('submit', handleRegister);
    }
});
