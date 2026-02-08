# Dondad Tech - E-commerce Website

A full-stack e-commerce website for premium devices (Phones, Laptops, Tablets & Accessories).

## How to Run

### Option 1: Backend + Frontend (Recommended)
1. Open this folder in VS Code
2. Install dependencies: `npm install`
3. Start the server: `npm start`
4. Open http://localhost:3000 in your browser

### Option 2: Frontend Only (localStorage)
1. Simply double-click on `index.html` to open it in your browser
2. Data will be stored in browser's localStorage

## API Endpoints

### Authentication
- `POST /api/register` - Register new user
- `POST /api/login` - Login user

### Products
- `GET /api/products` - Get all products (supports ?category=phones&search=iphone)
- `GET /api/products/:id` - Get single product
- `POST /api/products` - Add product (admin)
- `PUT /api/products/:id` - Update product (admin)
- `DELETE /api/products/:id` - Delete product (admin)

### Cart
- `GET /api/cart/:userId` - Get user's cart
- `POST /api/cart` - Add item to cart
- `PUT /api/cart/:userId/:productId` - Update cart item
- `DELETE /api/cart/:userId/:productId` - Remove item
- `DELETE /api/cart/:userId` - Clear cart

### Orders
- `POST /api/orders` - Create order
- `GET /api/orders/:userId` - Get user's orders
- `GET /api/orders` - Get all orders (admin)
- `PUT /api/orders/:id/status` - Update order status (admin)

### Users
- `GET /api/users` - Get all users (admin)

## Default Admin Account
- Email: `admin@dondad.com`
- Password: `admin123`

## Project Structure

- `server.js` - Express backend server
- `index.html` - Main landing page
- `shop.html` - Shop page with product listing
- `products.js` - Product data (frontend)
- `script.js` - Main application logic
- `cart.html` - Shopping cart page
- `checkout.html` - Checkout page
- `login.html` - User login
- `register.html` - User registration
- `admin.html` - Admin panel
- `style.css` - Main stylesheet

## Features

- User authentication (login/register)
- Admin panel for product management
- Shopping cart functionality
- Order creation and tracking
- Product search and filtering
- Responsive design
