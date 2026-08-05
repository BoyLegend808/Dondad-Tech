/**
 * RECTOR HUB — Supabase Client Setup
 * Configures connection to Supabase DB with automated fallback to local storage / static products.
 */

(function () {
  'use strict';

  // Supabase credentials
  const SUPABASE_URL = window.ENV_SUPABASE_URL || 'https://ftswypapxmvqemxwwclj.supabase.co';
  const SUPABASE_ANON_KEY = window.ENV_SUPABASE_ANON_KEY || 'sb_publishable_Ds8__ewXBIC3MuFppnfceQ_rFZWumfN';

  let supabaseClient = null;

  // Initialize client if library exists
  if (typeof supabase !== 'undefined' && SUPABASE_URL && SUPABASE_ANON_KEY) {
    try {
      supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
      console.log('⚡ Supabase client initialized successfully.');
    } catch (err) {
      console.warn('⚠️ Supabase init error:', err);
    }
  }

  // Unified API wrapper for products
  window.RectorDB = {
    async getProducts(category = 'all') {
      if (supabaseClient) {
        try {
          let query = supabaseClient.from('products').select('*');
          if (category !== 'all') {
            query = query.eq('category', category);
          }
          const { data, error } = await query;
          if (!error && data && data.length > 0) {
            return data;
          }
        } catch (err) {
          console.warn('Supabase fetch failed, falling back to local dataset.', err);
        }
      }

      // Local fallback
      if (typeof window.getProductsByCategory === 'function') {
        return window.getProductsByCategory(category);
      }
      return window.products || [];
    },

    async getProductById(id) {
      if (supabaseClient) {
        try {
          const { data, error } = await supabaseClient.from('products').select('*').eq('id', id).single();
          if (!error && data) return data;
        } catch (err) {
          console.warn('Supabase product lookup error:', err);
        }
      }

      if (typeof window.getProductById === 'function') {
        return window.getProductById(id);
      }
      return (window.products || []).find(p => p.id === parseInt(id));
    }
  };
})();
