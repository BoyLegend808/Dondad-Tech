const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const Order = require('../../models/Order');
const Product = require('../../models/Product');
const User = require('../../models/User');
const { requireAdmin } = require('../../middleware/auth');

// GET /api/admin/dashboard - Main dashboard stats
router.get('/', requireAdmin, async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const weekAgo = new Date(today);
    weekAgo.setDate(weekAgo.getDate() - 7);

    const [
      totalCustomers,
      totalOrders,
      pendingOrders,
      todaySales,
      totalRevenue,
      lowStockProducts,
      recentOrders,
      topProducts,
      orderStatusBreakdown
    ] = await Promise.all([
      // Total customers (non-admin users)
      User.countDocuments({ role: { $ne: 'admin' } }),
      
      // Total orders
      Order.countDocuments(),
      
      // Pending orders
      Order.countDocuments({ status: 'pending' }),
      
      // Today's sales (paid orders)
      Order.aggregate([
        { $match: { 
          createdAt: { $gte: today }, 
          paymentStatus: 'paid',
          status: { $ne: 'cancelled' }
        } },
        { $group: { _id: null, total: { $sum: '$subtotal' } } }
      ]),
      
      // Total lifetime revenue
      Order.aggregate([
        { $match: { 
          paymentStatus: 'paid',
          status: { $ne: 'cancelled' }
        } },
        { $group: { _id: null, total: { $sum: '$subtotal' } } }
      ]),
      
      // Low stock products (stock <= 5 and > 0)
      Product.countDocuments({ 
        stock: { $gt: 0, $lte: 5 } 
      }),
      
      // 10 most recent orders
      Order.find({ status: { $ne: 'cancelled' } })
        .populate('userId', 'name email')
        .sort({ createdAt: -1 })
        .limit(10)
        .lean(),
      
      // Top 5 products by sales (this week)
      Order.aggregate([
        { $match: { 
          createdAt: { $gte: weekAgo },
          paymentStatus: 'paid',
          status: { $ne: 'cancelled' }
        }},
        { $unwind: '$items' },
        { $group: {
          _id: '$items.productId',
          productName: { $first: '$items.productName' },
          quantity: { $sum: '$items.qty' },
          revenue: { $sum: { $multiply: ['$items.unitPrice', '$items.qty'] } }
        }},
        { $sort: { quantity: -1 } },
        { $limit: 5 },
        { $lookup: {
          from: 'products',
          localField: '_id',
          foreignField: '_id',
          as: 'product'
        }},
        { $addFields: { product: { $arrayElemAt: ['$product', 0] } } }
      ]),
      
      // Order status breakdown
      Order.aggregate([
        { $match: { status: { $ne: 'cancelled' } } },
        { $group: { _id: '$status', count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ])
    ]);

    res.json({
      todaySales: todaySales[0]?.total || 0,
      pendingOrders: pendingOrders,
      lowStockProducts,
      totalCustomers,
      totalOrders,
      totalRevenue: totalRevenue[0]?.total || 0,
      recentOrders,
      topProducts,
      orderStatusBreakdown,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Dashboard stats error:', error);
    res.status(500).json({ error: 'Failed to load dashboard stats' });
  }
});

module.exports = router;

