# Fix Admin Products Loading Issue - Products Show Loading Skeleton Only

## Plan Overview
**Issue**: Admin panel shows loading skeleton but never loads products  
**Root Cause**: Frontend calls wrong API endpoint (`/api/products` public) instead of `/api/admin/products` (admin protected)  
**Status**: ✅ Approved by user

## Steps (3/5 Complete)

### 1. ✅ Create TODO.md [DONE]
Track progress of the fix

### 2. ✅ Fix js/admin.js API endpoints [DONE]
- Change all `/api/products` → `/api/admin/products` for admin operations
- `loadProducts()`: `/api/products` → `/api/admin/products`
- `editProduct()`: `/api/products/:id` → `/api/admin/products/:id` 
- `deleteProduct()`: `/api/products/:id` → `/api/admin/products/:id`
- `product-form` submit: `/products` → `/admin/products`

### 3. ✅ Test server & seed products [DONE]
```bash
npm start
# Visit http://localhost:3000/api/seed-products (seeds public products)
# Login: admin@dondad.com / admin123
```

### 4. 🔄 Test admin panel [PENDING]
```
1. Visit http://localhost:3000/admin.html (or pages/admin/admin.html)
2. Login as admin
3. Verify products table loads (not stuck on "Loading...")
4. Check Network tab: /api/admin/products → 200 + products array
```

### 5. ✅ Complete & verify [PENDING]
- Products list loads with data
- Edit/Delete/Create work
- Network requests use correct admin endpoints

## Commands to Test
```bash
# Terminal 1: Start server
npm start

# Browser: Seed products (if empty)
http://localhost:3000/api/seed-products

# Browser: Test public products
http://localhost:3000/api/products

# Admin login
admin@dondad.com / admin123
```

## Expected Result
Admin table shows products like:
```
[Product Image] | iPhone 13 Pro Max | phones | ₦450,000 | [Edit][Delete]
[Product Image] | MacBook Pro 14    | laptops| ₦850,000 | [Edit][Delete]
```

---

**Next**: Test admin panel (Step 4)

