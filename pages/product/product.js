/**
 * Dondad Tech (Rector Hub) — Product Detail Page Logic
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

  async function initProductPage() {
    // 1. Render Related Products
    if (typeof window.renderProducts === 'function' && typeof window.products !== 'undefined') {
      window.renderProducts(window.products.slice(0, 4), 'related-products-grid');
    }

    // 2. Parse URL and load product details
    const container = document.getElementById('product-detail-container');
    if (!container) return;

    const urlParams = new URLSearchParams(window.location.search);
    const productId = urlParams.get('id');

    if (!productId) {
      container.innerHTML = '<p style="text-align:center; padding: 4rem; color: var(--text-danger);">Error: No product ID specified.</p>';
      return;
    }

    let product = null;

    // Try live/Supabase lookup wrapper first
    if (window.RectorDB && typeof window.RectorDB.getProductById === 'function') {
      try {
        product = await window.RectorDB.getProductById(productId);
      } catch (err) {
        console.warn('RectorDB query failed, checking window.products:', err);
      }
    }

    // Fallback to local products array
    if (!product && typeof window.products !== 'undefined') {
      product = window.products.find(p => String(p.id) === String(productId) || String(p._id) === String(productId));
    }

    if (!product) {
      container.innerHTML = '<p style="text-align:center; padding: 4rem; color: var(--text-danger);">Product not found.</p>';
      return;
    }

    // Update breadcrumb and document title
    document.title = `${product.name} - Rector Hub`;
    const breadcrumbName = document.getElementById('breadcrumb-product-name');
    if (breadcrumbName) {
      breadcrumbName.textContent = product.name;
    }

    // Resolve relative image path
    let imgSrc = product.image || 'images/logo.png';
    if (!imgSrc.startsWith('http') && !imgSrc.startsWith('/')) {
      imgSrc = '../../' + imgSrc;
    }

    // Render detail layout
    container.innerHTML = `
      <div class="product-detail-card">
        <div class="product-gallery">
          <div class="main-image-wrap">
            <img src="${imgSrc}" alt="${product.name}" onerror="this.src='../../images/logo.png'">
          </div>
        </div>
        <div class="product-info-wrap">
          <span class="badge badge-primary" style="width: fit-content;">${(product.category || 'gadget').toUpperCase()}</span>
          <h1 class="product-title">${product.name}</h1>
          <p class="product-price-large">₦${Number(product.price).toLocaleString()}</p>
          <p class="product-description">${product.desc || 'No description available for this item.'}</p>
          
          <div class="product-actions">
            <button class="btn btn-primary btn-lg" style="flex: 2;" onclick="if(typeof window.addToCart === 'function'){ window.addToCart(${product.id || `'${product._id}'`}) }"><i class="fas fa-cart-plus"></i> Add to Cart</button>
            <button class="btn btn-secondary btn-lg" style="flex: 1;" onclick="if(typeof window.toggleWishlist === 'function'){ window.toggleWishlist(${product.id || `'${product._id}'`}, this) }"><i class="fas fa-heart"></i> Save</button>
          </div>
        </div>
      </div>
    `;
  }

  ready(initProductPage);
})();
