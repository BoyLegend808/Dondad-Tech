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
          const { data, error } = await supabaseClient.from('products').select('*').or(`id.eq.${id},legacy_id.eq.${parseInt(id) || -1}`).single();
          if (!error && data) return data;
        } catch (err) {
          console.warn('Supabase product lookup error:', err);
        }
      }

      if (typeof window.getProductById === 'function') {
        return window.getProductById(id);
      }
      return (window.products || []).find(p => p.id === parseInt(id));
    },

    // Save or update product
    async saveProduct(product) {
      if (!supabaseClient) {
        throw new Error('Supabase client is not initialized.');
      }
      const isNew = !product.id;
      if (isNew) {
        const { data, error } = await supabaseClient.from('products').insert([product]).select().single();
        if (error) throw error;
        return data;
      } else {
        const { data, error } = await supabaseClient.from('products').update(product).eq('id', product.id).select().single();
        if (error) throw error;
        return data;
      }
    },

    // Delete product
    async deleteProduct(id) {
      if (!supabaseClient) {
        throw new Error('Supabase client is not initialized.');
      }
      const { error } = await supabaseClient.from('products').delete().eq('id', id);
      if (error) throw error;
      return true;
    },

    // Fetch dashboard stats / recent items
    async getDashboardStats() {
      if (!supabaseClient) return { totalProducts: 0, totalOrders: 0 };
      const { count: prodCount } = await supabaseClient.from('products').select('*', { count: 'exact', head: true });
      const { count: orderCount } = await supabaseClient.from('orders').select('*', { count: 'exact', head: true });
      return {
        totalProducts: prodCount || 0,
        totalOrders: orderCount || 0
      };
    },

    // Fetch all customers from Supabase profiles/users table
    async getCustomers() {
      if (!supabaseClient) return [];
      const { data, error } = await supabaseClient.from('profiles').select('*');
      if (error) throw error;
      return data || [];
    },

    // Fetch all orders from Supabase orders table
    async getOrders() {
      if (!supabaseClient) return [];
      const { data, error } = await supabaseClient.from('orders').select('*').order('created_at', { ascending: false });
      if (error) throw error;
      return data || [];
    },

    // Update order status in Supabase orders table
    async updateOrderStatus(orderId, status) {
      if (!supabaseClient) throw new Error('Supabase client not initialized');
      const { data, error } = await supabaseClient.from('orders').update({ status }).eq('id', orderId).select().single();
      if (error) throw error;
      return data;
    },

    // Authenticate user via Supabase users table
    async loginUser(email, password) {
      if (!supabaseClient) throw new Error('Database client not initialized');
      // Simple lookup based on seeded credentials
      const { data, error } = await supabaseClient.from('users').select('*').eq('email', email.trim().toLowerCase()).eq('password', password).single();
      if (error || !data) throw new Error('Invalid email address or password.');
      return data;
    },

    // Register user via Supabase users table
    async registerUser({ name, email, password, phone }) {
      if (!supabaseClient) throw new Error('Database client not initialized');
      const { data, error } = await supabaseClient.from('users').insert([{
        name,
        email: email.trim().toLowerCase(),
        password,
        phone: phone || '',
        role: 'user',
        is_email_verified: true
      }]).select().single();
      if (error) throw error;
      return data;
    }
  };

})();
