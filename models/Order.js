const mongoose = require('mongoose');

const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  userName: { type: String, required: true },
  userEmail: { type: String, required: true },
  userPhone: { type: String, required: true },
  items: [{
    productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    productName: { type: String },
    productImage: { type: String },
    qty: { type: Number },
    unitPrice: { type: Number },
    selectedVariant: {
      storage: { type: String, default: "" },
      ram: { type: String, default: "" },
      color: { type: String, default: "" }
    }
  }],
  deliveryInfo: {
    address: { type: String },
    method: { type: String },
    notes: { type: String },
    trackingNumber: { type: String, default: "" },
    estimatedDelivery: { type: Date },
    shippedDate: { type: Date },
    deliveredDate: { type: Date }
  },
  paymentMethod: { type: String },
  paymentStatus: { type: String, default: "pending" },
  paymentReference: { type: String, default: "" },
  subtotal: { type: Number },
  status: { type: String, default: "pending" },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

orderSchema.index({ createdAt: -1 });
orderSchema.index({ status: 1, createdAt: -1 });

module.exports = mongoose.model('Order', orderSchema);

