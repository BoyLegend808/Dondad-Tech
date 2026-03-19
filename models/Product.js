const mongoose = require('mongoose');

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

module.exports = mongoose.model('Product', productSchema);

