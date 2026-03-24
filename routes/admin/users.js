const express = require('express');
const router = express.Router();
const { User, Order } = require('../../models');
const { requireAdmin, isValidObjectId } = require('../../middleware/auth');

// GET /api/admin/users - List all customers with order stats
router.get('/', requireAdmin, async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = Math.min(parseInt(req.query.limit || '50', 10), 100);
    
    // Get all non-admin users
    const users = await User.find({ role: { $ne: 'admin' } })
      .select('-password')
      .sort({ createdAt: -1 })
      .lean();
    
    // Get order stats for each user
    const usersWithStats = await Promise.all(users.map(async (user) => {
      const orders = await Order.find({ userId: user._id }).lean();
      const orderCount = orders.length;
      const totalSpent = orders.reduce((sum, order) => sum + (order.subtotal || 0), 0);
      return {
        ...user,
        orderCount,
        totalSpent
      };
    }));
    
    const total = usersWithStats.length;
    const paginatedUsers = usersWithStats.slice((page - 1) * limit, page * limit);
    
    res.json({
      users: paginatedUsers,
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

// GET /api/admin/users/:id - Customer details with stats
router.get('/:id', requireAdmin, async (req, res) => {
  try {
    const id = req.params.id;
    if (!isValidObjectId(id)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }
    
    const [user, orders] = await Promise.all([
      User.findById(id).select('-password -resetPasswordToken').lean(),
      Order.find({ userId: id }).sort({ createdAt: -1 }).lean()
    ]);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const totalSpent = orders.reduce((sum, order) => sum + (order.subtotal || 0), 0);
    
    res.json({
      user,
      stats: {
        totalOrders: orders.length,
        totalSpent,
        avgOrderValue: orders.length > 0 ? Math.round(totalSpent / orders.length) : 0,
        recentOrders: orders.slice(0, 5)
      }
    });
  } catch (error) {
    console.error('Admin user details error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
});

module.exports = router;

