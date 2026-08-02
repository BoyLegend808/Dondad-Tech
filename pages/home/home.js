/**
 * Dondad Tech (Rector Hub) — Home Page Logic
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

  function initHomeSearch() {
    const searchInput = document.getElementById('home-search');
    if (!searchInput) return;

    searchInput.addEventListener('keypress', function (e) {
      if (e.key === 'Enter') {
        const query = this.value.trim();
        if (query) {
          window.location.href = `../shop/shop.html?search=${encodeURIComponent(query)}`;
        }
      }
    });
  }

  ready(initHomeSearch);
})();
