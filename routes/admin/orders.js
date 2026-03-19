const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Order = require('../../models/Order'); // Adjust path based on your models
const User = require('../../models/User');
const { requireAdmin, isValidObjectId } = require('../../middleware/auth');

// Helper: Sanitize text
function sanitizeText(input = '', maxLen = 500) {
  return String(input || '').trim().replace(/\s+/g, ' ').slice(0, maxLen);
}

// GET /api/admin/orders - Get all orders (admin dashboard)
router.get('/', requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 100);
    const status = sanitizeText(req.query.status || '');
    const search = sanitizeText(req.query.search || '');

    const query = {};
    if (status) query.status = status;
    if (search) {
      query.$or = [
        { userName: { $regex: search, $options: 'i' } },
        { userEmail: { $regex: search, $options: 'i' } },
        { _id: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;
    const [orders, total] = await Promise.all([
      Order.find(query)
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Order.countDocuments(query)
    ]);

    res.json({
      orders,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin orders list error:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// GET /api/admin/orders/:id - Get single order details
router.get('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid order ID' });
    }

    const order = await Order.findById(id)
      .populate('userId', 'name email phone')
      .lean();

    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    res.json(order);
  } catch (error) {
    console.error('Admin order details error:', error);
    res.status(500).json({ error: 'Failed to fetch order' });
  }
});

// PUT /api/admin/orders/:id - Update order status/details
router.put('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid order ID' });
    }

    const order = await Order.findById(id);
    if (!order) {
      return res.status(404).json({ error: 'Order not found' });
    }

    const allowedStatuses = ['pending', 'confirmed', 'processing', 'shipped', 'delivered', 'cancelled'];
    const status = sanitizeText(req.body.status, 24);
    
    if (status && !allowedStatuses.includes(status)) {
      return res.status(400).json({ error: 'Invalid status' });
    }

    const update = { updatedAt: new Date() };
    
    if (status) update.status = status;
    if (req.body.trackingNumber) update['deliveryInfo.trackingNumber'] = sanitizeText(req.body.trackingNumber, 80);
    if (req.body.estimatedDelivery) update['deliveryInfo.estimatedDelivery'] = new Date(req.body.estimatedDelivery);
    
    // Auto-set timestamps
    if (status === 'shipped') update['deliveryInfo.shippedDate'] = new Date();
    if (status === 'delivered') update['deliveryInfo.deliveredDate'] = new Date();

    const updatedOrder = await Order.findByIdAndUpdate(id, update, { new: true })
      .populate('userId', 'name email');

    res.json({ 
      success: true, 
      order: updatedOrder,
      message: `Order status updated to ${status || 'updated'}`
    });
  } catch (error) {
    console.error('Admin update order error:', error);
    res.status(500).json({ error: 'Failed to update order' });
  }
});

// GET /api/admin/orders/stats - Quick order statistics
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [totalOrders, pendingOrders, todaySales, totalRevenue] = await Promise.all([
      Order.countDocuments(),
      Order.countDocuments({ status: 'pending' }),
      Order.aggregate([
        { $match: { createdAt: { $gte: today }, paymentStatus: 'paid' } },
        { $group: { _id: null, total: { $sum: '$subtotal' } } }
      ]),
      Order.aggregate([
        { $match: { paymentStatus: 'paid' } },
        { $group: { _id: null, total: { $sum: '$subtotal' } } }
      ])
    ]);

    res.json({
      totalOrders,
      pendingOrders,
      todaySales: todaySales[0]?.total || 0,
      totalRevenue: totalRevenue[0]?.total || 0,
      avgOrderValue: totalOrders > 0 ? Math.round((totalRevenue[0]?.total || 0) / totalOrders) : 0
    });
  } catch (error) {
    console.error('Admin order stats error:', error);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

module.exports = router;

