# Product Variants Implementation Plan

## Overview
Add product variants (Storage, RAM, Color) with different prices for each variant option. Admin can configure variants per product, and users can select variants when adding to cart.

## Database Schema Changes

### Product Schema (`server.js`)
```javascript
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true }, // Base price
  image: { type: String, required: true },
  desc: { type: String, default: "" },
  // New variant fields
  hasVariants: { type: Boolean, default: false },
  variants: {
    storage: [{
      option: String,      // e.g., "128GB", "256GB", "512GB"
      priceModifier: { type: Number, default: 0 }, // Add to base price
      stock: { type: Number, default: 0 }
    }],
    ram: [{
      option: String,      // e.g., "4GB", "8GB", "16GB"
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 }
    }],
    color: [{
      option: String,      // e.g., "Black", "White", "Blue"
      priceModifier: { type: Number, default: 0 },
      stock: { type: Number, default: 0 },
      image: String        // Optional color-specific image
    }]
  }
});
```

### Cart Schema (`server.js`)
```javascript
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  productId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Product",
    required: true,
  },
  qty: { type: Number, default: 1 },
  // New variant selection
  selectedVariant: {
    storage: String,
    ram: String,
    color: String
  },
  // Store price at time of addition
  unitPrice: { type: Number, required: true }
});
```

## File Changes Summary

### 1. `server.js`
- [ ] Update productSchema with variant fields
- [ ] Update cartSchema with variant fields
- [ ] Add migration endpoint to update existing products
- [ ] Update cart API endpoints to handle variants

### 2. `admin.html`
- [ ] Add "Has Variants" checkbox toggle
- [ ] Add dynamic variant input fields (storage, ram, color)
- [ ] Each variant option needs: option name, price modifier, stock
- [ ] "Add Option" button for each variant type

### 3. `admin.js` (or inline script in admin.html)
- [ ] Handle variant checkbox toggle
- [ ] Add/remove variant option rows dynamically
- [ ] Collect variant data for form submission
- [ ] Populate variant fields when editing product

### 4. `product.html`
- [ ] Add variant selectors (dropdowns or button groups)
- [ ] Show price based on selected variant
- [ ] Update "Add to Cart" to include selected variants
- [ ] Show variant availability (out of stock indication)

### 5. `cart.html`
- [ ] Display selected variants for each cart item
- [ ] Show the final price (base + modifiers)
- [ ] Allow variant changes from cart (optional)

### 6. `shop.html` & `shop.js`
- [ ] Simplify product cards (remove description)
- [ ] Keep: image, name, price
- [ ] If product has variants, show "From ₦X" format

## API Endpoints

### Existing Endpoints (to be updated)
- `GET /api/products` - Returns products with variant info
- `GET /api/products/:id` - Returns product with variants
- `POST /api/products` - Accepts variant data
- `PUT /api/products/:id` - Accepts variant data
- `POST /api/cart/:userId/:productId` - Accepts variant selection
- `PUT /api/cart/:userId/:productId` - Accepts variant updates

### New Endpoints
- `POST /api/products/:id/migrate-variants` - Add variant fields to existing products (run once)

## Implementation Order

1. **Phase 1: Backend**
   - Update MongoDB schemas
   - Add migration endpoint
   - Test schema changes

2. **Phase 2: Admin Panel**
   - Add variant UI components
   - Handle form submission with variants
   - Test adding/editing products with variants

3. **Phase 3: Product Page**
   - Add variant selectors
   - Update price display based on selection
   - Pass variants to cart

4. **Phase 4: Cart**
   - Display variants in cart items
   - Calculate correct prices

5. **Phase 5: Shop Page**
   - Simplify product cards
   - Test filtering and search

## UI/UX Details

### Admin Variant Interface
```
[ ] Enable Product Variants

Storage Options:
+ Add Storage Option
[ 128GB  ] [+₦0] [Stock: 10] [X]
[ 256GB  ] [+₦15000] [Stock: 10] [X]
[ 512GB  ] [+₦35000] [Stock: 5] [X]

RAM Options:
+ Add RAM Option
[ 4GB  ] [+₦0] [Stock: 10] [X]
[ 8GB  ] [+₦10000] [Stock: 10] [X]

Color Options:
+ Add Color Option
[ Black ] [+₦0] [Stock: 10] [X]
[ White ] [+₦0] [Stock: 10] [X]
[ Blue  ] [+₦2000] [Stock: 8] [X]
```

### Product Page Variant Selectors
```
Product: iPhone 13 Pro Max

Price: ₦450,000

Select Storage:
[ 128GB ] [ 256GB+] [ 512GB+ ]

Select RAM:
[ 4GB ] [ 8GB+ ]

Select Color:
[ ⚫ Black ] [ ⚪ White ] [ 🔵 Blue+ ]

Quantity: [-] 1 [+]

[ ADD TO CART ]
```

### Cart Item Display
```
[iPhone 13 Pro Max image]

iPhone 13 Pro Max
256GB | 8GB RAM | Blue
₦465,000 × 1 = ₦465,000
```

## Price Calculation
- Base Price: ₦450,000
- Storage (256GB): +₦15,000
- RAM (8GB): +₦10,000
- Color (Blue): +₦2,000
- **Final Price: ₦477,000**

## Migration Strategy
1. Add new fields to existing products via migration endpoint
2. Set `hasVariants: false` for existing products
3. Admin can enable variants per product
4. Products with variants enabled show variant selectors

## Notes
- Variants primarily for phones category
- Accessories will have `hasVariants: false`
- Price modifiers can be positive or negative
- Stock tracking per variant option
