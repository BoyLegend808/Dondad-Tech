const express = require('express');
const router = express.Router();
const User = require('../../models/User');
const Order = require('../../models/Order');
const { requireAdmin, isValidObjectId } = require('../../middleware/auth');

// GET /api/admin/users - Get all customers (non-admin users)
router.get('/', requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 100);
    const search = sanitizeText(req.query.search || '');

    const query = { role: { $ne: 'admin' } };
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const skip = (page - 1) * limit;
    const [users, total] = await Promise.all([
      User.find(query)
        .select('-password')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      User.countDocuments(query)
    ]);

    // Add order stats for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const orders = await Order.find({ userId: user._id })
          .select('subtotal status createdAt')
          .lean();
        
        const totalOrders = orders.length;
        const totalSpent = orders.reduce((sum, order) => sum + (order.subtotal || 0), 0);
        const recentOrderDate = orders.length > 0 
          ? new Date(Math.max(...orders.map(o => new Date(o.createdAt).getTime())))
          : null;

        return {
          ...user,
          totalOrders,
          totalSpent,
          lastOrderDate: recentOrderDate ? recentOrderDate.toLocaleDateString() : 'Never',
          avgOrderValue: totalOrders > 0 ? Math.round(totalSpent / totalOrders) : 0
        };
      })
    );

    res.json({
      users: usersWithStats,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Admin users list error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

// GET /api/admin/users/:id - Get single customer details + stats
router.get('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    const [user, orders] = await Promise.all([
      User.findById(id).select('-password resetPasswordToken verificationToken').lean(),
      Order.find({ userId: id })
        .populate('items.productId', 'name image')
        .sort({ createdAt: -1 })
        .lean()
    ]);

    if (!user || user.role === 'admin') {
      return res.status(404).json({ error: 'Customer not found' });
    }

    const totalOrders = orders.length;
    const totalSpent = orders.reduce((sum, order) => sum + (order.subtotal || 0), 0);
    const orderStatusBreakdown = {};
    orders.forEach(order => {
      orderStatusBreakdown[order.status] = (orderStatusBreakdown[order.status] || 0) + 1;
    });

    res.json({
      user,
      stats: {
        totalOrders,
        totalSpent,
        avgOrderValue: totalOrders > 0 ? Math.round(totalSpent / totalOrders) : 0,
        orderStatusBreakdown,
        recentOrders: orders.slice(0, 5)
      }
    });
  } catch (error) {
    console.error('Admin user details error:', error);
    res.status(500).json({ error: 'Failed to fetch customer' });
  }
});

// GET /api/admin/users/stats - Customer statistics summary
router.get('/stats', requireAdmin, async (req, res) => {
  try {
    const [
      totalCustomers,
      newCustomersToday,
      activeCustomers,
      topCustomers
    ] = await Promise.all([
      // Total non-admin users
      User.countDocuments({ role: { $ne: 'admin' } }),
      
      // New customers today
      User.countDocuments({
        role: { $ne: 'admin' },
        createdAt: { $gte: new Date().setHours(0, 0, 0, 0) }
      }),
      
      // Customers with orders (active)
      User.countDocuments({
        role: { $ne: 'admin' },
        'orders.0': { $exists: true }
      }),
      
      // Top 10 customers by spending
      Order.aggregate([
        { $match: { status: { $ne: 'cancelled' }, paymentStatus: 'paid' } },
        { $group: {
          _id: '$userId',
          totalSpent: { $sum: '$subtotal' },
          orderCount: { $sum: 1 }
        }},
        { $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'user',
          pipeline: [{ $match: { role: { $ne: 'admin' } } }, { $project: { name: 1, email: 1 } }]
        }},
        { $unwind: '$user' },
        { $sort: { totalSpent: -1 } },
        { $limit: 10 },
        { $project: {
          user: 1,
          totalSpent: 1,
          orderCount: 1,
          avgOrder: { $divide: ['$totalSpent', '$orderCount'] }
        }}
      ])
    ]);

    res.json({
      totalCustomers,
      newCustomersToday,
      activeCustomers,
      topCustomers,
      avgCustomerLifetimeValue: topCustomers.length > 0 
        ? Math.round(topCustomers.reduce((sum, c) => sum + c.totalSpent, 0) / topCustomers.length)
        : 0
    });
  } catch (error) {
    console.error('Admin customer stats error:', error);
    res.status(500).json({ error: 'Failed to fetch customer stats' });
  }
});

module.exports = router;

