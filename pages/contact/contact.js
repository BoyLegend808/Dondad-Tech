/**
 * Dondad Tech (Rector Hub) — Contact Page Logic
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

  function initContactForm() {
    const form = document.getElementById('contact-form');
    if (!form) return;

    form.addEventListener('submit', function (e) {
      e.preventDefault();
      alert('Thank you for contacting Rector Hub! We will get back to you shortly.');
      form.reset();
    });
  }

  ready(initContactForm);
})();
