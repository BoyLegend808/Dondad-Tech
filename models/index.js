const mongoose = require('mongoose');

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phone: { type: String, default: "" },
  role: { type: String, default: "user" },
  isEmailVerified: { type: Boolean, default: false },
  verificationToken: { type: String, default: "" },
  googleId: { type: String, default: "" },
  facebookId: { type: String, default: "" },
  profilePicture: { type: String, default: "" },
  resetPasswordToken: { type: String, default: "" },
  resetPasswordExpires: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now },
});

userSchema.index({ email: 1 });
userSchema.index({ googleId: 1 });
userSchema.index({ facebookId: 1 });

// Product Schema
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, default: "images/logo.png" },
  desc: { type: String, default: "" },
  fullDesc: { type: String, default: "" },
  id: { type: Number, default: null },
  stock: { type: Number, default: 0 },
  hasVariants: { type: Boolean, default: false },
  variants: {
    storage: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 }
    }],
    ram: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 }
    }],
    color: [{
      option: { type: String, default: "" },
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 },
      image: { type: String, default: "" }
    }]
  },
  createdAt: { type: Date, default: Date.now }
});

productSchema.index({ category: 1, price: 1 });
productSchema.index({ name: "text", desc: "text" });
productSchema.index({ id: 1 });

// Order Schema
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

// Export models
module.exports = {
  User: mongoose.models.User || mongoose.model('User', userSchema),
  Product: mongoose.models.Product || mongoose.model('Product', productSchema),
  Order: mongoose.models.Order || mongoose.model('Order', orderSchema)
};

