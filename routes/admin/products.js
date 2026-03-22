const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Product = require('../../models/Product'); // Adjust path based on your models location
const { requireAdmin, isValidObjectId } = require('../../middleware/auth');

// Helper: Sanitize text input
function sanitizeText(input = '', maxLen = 500) {
  return String(input || '').trim().replace(/\s+/g, ' ').slice(0, maxLen);
}

// Helper: Sanitize image URL/base64
function sanitizeImageInput(input = '', maxLen = 5_000_000) {
  const trimmed = String(input || '').trim();
  if (!trimmed) return '';
  
  // Valid data URL
  if (trimmed.startsWith('data:image/')) {
    return trimmed.slice(0, maxLen);
  }
  
  // Valid HTTP URL
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    return trimmed.slice(0, maxLen);
  }
  
  return '';
}

// Helper: Parse positive money value
function parseMoney(value, fallback = null) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

// Helper: Parse positive integer
function parsePositiveInt(value, fallback = 1) {
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

// GET /api/admin/products - List all products (admin only)
router.get('/', requireAdmin, async (req, res) => {
  try {
    const page = parsePositiveInt(req.query.page, 1);
    const limit = Math.min(parsePositiveInt(req.query.limit, 50), 100);
    const search = sanitizeText(req.query.search || '');
    const category = sanitizeText(req.query.category || '').toLowerCase();

    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { desc: { $regex: search, $options: 'i' } }
      ];
    }
    if (category && category !== 'all') {
      query.category = category;
    }

    const skip = (page - 1) * limit;
    const [products, total] = await Promise.all([
      Product.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Product.countDocuments(query)
    ]);

    console.log(`[ADMIN-PRODUCTS] Serving ${products.length} products (page ${page}) to admin ${req.user?._id}`);
    
    res.json({
      success: true,
      products,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin products list error:', error);
    res.status(500).json({ 
      success: false,
      error: 'Failed to fetch products' 
    });
  }
});

// POST /api/admin/products - Create new product
router.post('/', requireAdmin, async (req, res) => {
  try {
    const name = sanitizeText(req.body.name, 120);
    const category = sanitizeText(req.body.category || 'accessories', 40).toLowerCase();
    const price = parseMoney(req.body.price);
    const image = sanitizeImageInput(req.body.image);
    const desc = sanitizeText(req.body.desc, 600);
    const fullDesc = sanitizeText(req.body.fullDesc, 4000);
    const stock = parsePositiveInt(req.body.stock, 0);

    if (!name || !price || price <= 0) {
      return res.status(400).json({ error: 'Name and valid price required' });
    }

    const allowedCategories = ['phones', 'laptops', 'tablets', 'accessories'];
    if (!allowedCategories.includes(category)) {
      return res.status(400).json({ error: 'Invalid category' });
    }

    const productData = {
      name,
      category,
      price,
      desc: desc || '',
      fullDesc: fullDesc || '',
      stock,
      hasVariants: Boolean(req.body.hasVariants),
      image: image || 'images/logo.png'
    };

    // Handle variants safely
    if (req.body.variants && typeof req.body.variants === 'object') {
      productData.variants = {
        storage: (req.body.variants.storage || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0)
        })).filter(v => v.option),
        
        ram: (req.body.variants.ram || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0)
        })).filter(v => v.option),
        
        color: (req.body.variants.color || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0),
          image: sanitizeImageInput(v.image)
        })).filter(v => v.option)
      };
    }

    const product = await Product.create(productData);
    res.status(201).json(product);
  } catch (error) {
    console.error('Admin create product error:', error);
    res.status(500).json({ error: 'Failed to create product' });
  }
});

// PUT /api/admin/products/:id - Update product
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const update = {};
    if (req.body.name !== undefined) update.name = sanitizeText(req.body.name, 120);
    if (req.body.category !== undefined) {
      const cat = sanitizeText(req.body.category, 40).toLowerCase();
      update.category = ['phones','laptops','tablets','accessories'].includes(cat) ? cat : undefined;
    }
    if (req.body.price !== undefined) {
      const price = parseMoney(req.body.price);
      if (price !== null) update.price = price;
    }
    if (req.body.image !== undefined) {
      update.image = sanitizeImageInput(req.body.image);
    }
    if (req.body.desc !== undefined) update.desc = sanitizeText(req.body.desc, 600);
    if (req.body.fullDesc !== undefined) update.fullDesc = sanitizeText(req.body.fullDesc, 4000);
    if (req.body.stock !== undefined) update.stock = parsePositiveInt(req.body.stock, 0);
    if (req.body.hasVariants !== undefined) update.hasVariants = Boolean(req.body.hasVariants);

    // Variants
    if (req.body.variants && typeof req.body.variants === 'object') {
      update.variants = {
        storage: (req.body.variants.storage || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0)
        })).filter(v => v.option),
        
        ram: (req.body.variants.ram || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0)
        })).filter(v => v.option),
        
        color: (req.body.variants.color || []).map(v => ({
          option: sanitizeText(v.option, 40),
          priceModifier: parseMoney(v.priceModifier, 0),
          stock: parsePositiveInt(v.stock, 0),
          image: sanitizeImageInput(v.image)
        })).filter(v => v.option)
      };
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: 'No valid fields to update' });
    }

    const product = await Product.findByIdAndUpdate(id, update, { new: true });
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json(product);
  } catch (error) {
    console.error('Admin update product error:', error);
    res.status(500).json({ error: 'Failed to update product' });
  }
});

// DELETE /api/admin/products/:id
router.delete('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid product ID' });
    }

    const product = await Product.findByIdAndDelete(id);
    if (!product) {
      return res.status(404).json({ error: 'Product not found' });
    }

    res.json({ success: true, message: 'Product deleted' });
  } catch (error) {
    console.error('Admin delete product error:', error);
    res.status(500).json({ error: 'Failed to delete product' });
  }
});

module.exports = router;

