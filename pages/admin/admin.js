/**
 * Dondad Tech (Rector Hub) — Admin Page Logic
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

  function initAdminEvents() {
    const logoutBtns = document.querySelectorAll('.logout-trigger');
    logoutBtns.forEach(btn => {
      btn.addEventListener('click', function (e) {
        e.preventDefault();
        if (typeof window.handleLogout === 'function') {
          window.handleLogout();
        }
      });
    });

    // Make utility forms and variant builders globally accessible from admin.html inline triggers
    window.addVariant = function(type, data) {
      if (typeof window.addVariant === 'function' && window.addVariant !== addVariant) {
        window.addVariant(type, data);
      } else if (document.getElementById('storage-container')) {
        // Fallback or binding reference to helper inside admin-app.js
        const appModuleAdd = window.addVariant;
        if (appModuleAdd && appModuleAdd.name !== 'addVariant') {
          appModuleAdd(type, data);
        }
      }
    };
  }

  ready(initAdminEvents);
})();

