/**
 * Dondad Tech (Rector Hub) — Shop Page Logic
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

  let activeCategory = 'all';

  async function applyCombinedFilter() {
    let prods = [];
    if (window.RectorDB && typeof window.RectorDB.getProducts === 'function') {
      prods = await window.RectorDB.getProducts(activeCategory);
    } else {
      prods = typeof window.products !== 'undefined' ? [...window.products] : [];
      if (activeCategory !== 'all') {
        prods = prods.filter(p => p.category === activeCategory);
      }
    }
    const searchQuery = (document.getElementById('search')?.value || '').toLowerCase().trim();
    const sortVal = document.getElementById('sort-select')?.value || 'default';

    if (searchQuery) {
      prods = prods.filter(p => {
        const nameMatch = (p.name || '').toLowerCase().includes(searchQuery);
        const descMatch = (p.desc || '').toLowerCase().includes(searchQuery);
        const catMatch = (p.category || '').toLowerCase().includes(searchQuery);
        const priceMatch = String(p.price || '').includes(searchQuery);
        return nameMatch || descMatch || catMatch || priceMatch;
      });
    }

    if (sortVal === 'price-low') {
      prods.sort((a, b) => a.price - b.price);
    } else if (sortVal === 'price-high') {
      prods.sort((a, b) => b.price - a.price);
    } else if (sortVal === 'name') {
      prods.sort((a, b) => a.name.localeCompare(b.name));
    } else if (sortVal === 'under-200k') {
      prods = prods.filter(p => p.price < 200000);
    } else if (sortVal === '200k-500k') {
      prods = prods.filter(p => p.price >= 200000 && p.price <= 500000);
    } else if (sortVal === 'above-500k') {
      prods = prods.filter(p => p.price > 500000);
    } else if (sortVal === 'featured') {
      prods = prods.filter(p => p.price > 300000);
    }

    if (typeof window.renderProducts === 'function') {
      window.renderProducts(prods, 'product-grid');
    }
  }

  async function setupFilters() {
    let prods = [];
    if (window.RectorDB && typeof window.RectorDB.getProducts === 'function') {
      prods = await window.RectorDB.getProducts(activeCategory);
    } else {
      prods = typeof window.products !== 'undefined' ? [...window.products] : [];
    }

    if (typeof window.renderProducts === 'function') {
      window.renderProducts(prods, 'product-grid');
    }

    const filterBtns = document.querySelectorAll('.filter-btn');
    filterBtns.forEach(btn => {
      btn.addEventListener('click', async function () {
        filterBtns.forEach(b => b.classList.remove('active'));
        this.classList.add('active');
        activeCategory = this.getAttribute('data-category') || 'all';
        applyCombinedFilter();
      });
    });

    const sortSelect = document.getElementById('sort-select');
    if (sortSelect) {
      sortSelect.addEventListener('change', applyCombinedFilter);
    }

    const searchInput = document.getElementById('search');
    if (searchInput) {
      searchInput.addEventListener('input', applyCombinedFilter);
    }
  }

  ready(setupFilters);
})();
