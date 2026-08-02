/**
 * RECTOR HUB — Global UI/UX Features Module
 * Implements Wishlist, Quick View Modal, Floating WhatsApp Button, and Skeleton Loaders.
 */

(function () {
  'use strict';

  function ready(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn);
    } else {
      fn();
    }
  }

  // 1. Wishlist Management (Local Storage)
  const WISHLIST_KEY = 'rector_wishlist';

  function getWishlist() {
    return JSON.parse(localStorage.getItem(WISHLIST_KEY) || '[]');
  }

  function toggleWishlist(productId, btn) {
    let wishlist = getWishlist();
    const id = parseInt(productId);
    const index = wishlist.indexOf(id);

    if (index > -1) {
      wishlist.splice(index, 1);
      if (btn) btn.classList.remove('active');
      if (window.showToast) window.showToast('Removed from Wishlist', 'info');
    } else {
      wishlist.push(id);
      if (btn) btn.classList.add('active');
      if (window.showToast) window.showToast('Added to Wishlist! ❤️', 'success');
    }
    localStorage.setItem(WISHLIST_KEY, JSON.stringify(wishlist));
  }

  // 2. Quick View Modal
  function createQuickViewModal() {
    if (document.getElementById('quickview-modal')) return;

    const modalHTML = `
      <div id="quickview-modal" class="quickview-modal-backdrop">
        <div class="quickview-card">
          <button class="quickview-close" id="quickview-close-btn" aria-label="Close modal">&times;</button>
          <div style="background: var(--bg-2); border-radius: var(--radius-lg); padding: 1rem; display: flex; align-items: center; justify-content: center;">
            <img id="qv-img" src="" alt="" style="max-height: 260px; object-fit: contain;">
          </div>
          <div style="display: flex; flex-direction: column; justify-content: center; gap: 0.75rem;">
            <span id="qv-badge" class="badge badge-primary" style="width: fit-content;"></span>
            <h2 id="qv-title" style="font-size: 1.5rem;"></h2>
            <p id="qv-desc" style="color: var(--text-muted); font-size: 0.9rem;"></p>
            <div style="display: flex; align-items: baseline; gap: 0.5rem; margin-top: 0.5rem;">
              <span id="qv-price" style="font-size: 1.75rem; font-weight: 800; color: var(--primary);"></span>
              <span id="qv-old-price" style="font-size: 1rem; color: var(--text-muted); text-decoration: line-through;"></span>
            </div>
            <div style="display: flex; gap: 0.75rem; margin-top: 1rem;">
              <button id="qv-add-btn" class="btn btn-primary" style="flex: 1;"><i class="fas fa-cart-plus"></i> Add to Cart</button>
              <a id="qv-detail-link" href="#" class="btn btn-secondary"><i class="fas fa-external-link-alt"></i> Details</a>
            </div>
          </div>
        </div>
      </div>
    `;
    document.body.insertAdjacentHTML('beforeend', modalHTML);

    const modal = document.getElementById('quickview-modal');
    const closeBtn = document.getElementById('quickview-close-btn');

    closeBtn.addEventListener('click', () => modal.classList.remove('active'));
    modal.addEventListener('click', (e) => {
      if (e.target === modal) modal.classList.remove('active');
    });
  }

  function openQuickView(productId) {
    createQuickViewModal();
    const product = typeof window.getProductById === 'function' ? window.getProductById(productId) : null;
    if (!product) return;

    const modal = document.getElementById('quickview-modal');
    const currentPath = window.location.pathname;
    const isSubfolder = currentPath.includes('/pages/');
    const pathPrefix = isSubfolder ? '../../' : '';

    let imgSrc = product.image || 'images/logo.png';
    if (isSubfolder && !imgSrc.startsWith('http') && !imgSrc.startsWith('/')) {
      imgSrc = pathPrefix + imgSrc;
    }

    document.getElementById('qv-img').src = imgSrc;
    document.getElementById('qv-title').textContent = product.name;
    document.getElementById('qv-desc').textContent = product.desc || '';
    document.getElementById('qv-badge').textContent = product.category.toUpperCase();
    document.getElementById('qv-price').textContent = `₦${Number(product.price).toLocaleString()}`;
    document.getElementById('qv-old-price').textContent = product.old_price ? `₦${Number(product.old_price).toLocaleString()}` : '';
    
    const addBtn = document.getElementById('qv-add-btn');
    addBtn.onclick = () => {
      if (typeof window.addToCart === 'function') {
        window.addToCart(product.id);
      }
      modal.classList.remove('active');
    };

    const detailLink = document.getElementById('qv-detail-link');
    detailLink.href = isSubfolder ? `../product/product.html?id=${product.id}` : `pages/product/product.html?id=${product.id}`;

    modal.classList.add('active');
  }

  // 3. Floating WhatsApp Direct Support Button
  function injectWhatsAppWidget() {
    if (document.querySelector('.whatsapp-float-btn')) return;
    const waLink = `https://wa.me/2348012345678?text=${encodeURIComponent('Hello Rector Hub! I have an inquiry about a gadget.')}`;
    const btnHTML = `
      <a href="${waLink}" target="_blank" rel="noopener noreferrer" class="whatsapp-float-btn" aria-label="Chat on WhatsApp" title="Direct WhatsApp Support">
        <i class="fab fa-whatsapp"></i>
      </a>
    `;
    document.body.insertAdjacentHTML('beforeend', btnHTML);
  }

  // Expose global methods
  window.toggleWishlist = toggleWishlist;
  window.openQuickView = openQuickView;

  ready(() => {
    createQuickViewModal();
    injectWhatsAppWidget();
  });
})();
