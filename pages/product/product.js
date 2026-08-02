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

  function initProductPage() {
    if (typeof window.renderProducts === 'function' && typeof window.products !== 'undefined') {
      window.renderProducts(window.products.slice(0, 4), 'related-products-grid');
    }
  }

  ready(initProductPage);
})();
