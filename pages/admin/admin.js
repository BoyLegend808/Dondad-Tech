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
  }

  ready(initAdminEvents);
})();
