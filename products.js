// Product data for Dondad Tech
const products = [
    // Phones
    { id: 1, name: "iPhone 13 Pro Max", category: "phones", price: 450000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "256GB, A15 chip, triple camera" },
    { id: 2, name: "iPhone 13 Pro", category: "phones", price: 400000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "256GB, A15 chip, triple camera" },
    { id: 3, name: "iPhone 13", category: "phones", price: 350000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A15 chip, dual camera" },
    { id: 4, name: "iPhone 12 Pro Max", category: "phones", price: 320000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A14 chip" },
    { id: 5, name: "iPhone 12", category: "phones", price: 280000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "128GB, A14 chip, dual camera" },
    { id: 6, name: "iPhone 11", category: "phones", price: 220000, image: "Iphone 11/iphone_113-removebg-preview.png", desc: "64GB, A13 chip, triple camera" },
    { id: 7, name: "iPhone XS Max", category: "phones", price: 180000, image: "xs.png", desc: "64GB, A12 chip, dual camera" },
    { id: 8, name: "iPhone XR", category: "phones", price: 150000, image: "xs.png", desc: "64GB, A12 chip, single camera" },
    
    // Laptops
    { id: 9, name: "MacBook Pro 14 inch", category: "laptops", price: 850000, image: "hero img.png", desc: "M1 Pro, 16GB RAM, 512GB SSD" },
    { id: 10, name: "MacBook Air M2", category: "laptops", price: 650000, image: "hero img.png", desc: "M2 chip, 8GB RAM, 256GB SSD" },
    { id: 11, name: "Dell XPS 13", category: "laptops", price: 550000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD" },
    { id: 12, name: "HP Spectre x360", category: "laptops", price: 480000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD, 2-in-1" },
    { id: 13, name: "Lenovo ThinkPad X1", category: "laptops", price: 520000, image: "hero img.png", desc: "Intel i7, 16GB RAM, 512GB SSD" },
    
    // Tablets
    { id: 14, name: "iPad Pro 12.9 inch", category: "tablets", price: 550000, image: "hero img.png", desc: "M1 chip, 128GB, WiFi" },
    { id: 15, name: "iPad Air", category: "tablets", price: 350000, image: "hero img.png", desc: "M1 chip, 64GB, WiFi" },
    { id: 16, name: "iPad 10th Gen", category: "tablets", price: 250000, image: "hero img.png", desc: "A14 chip, 64GB, WiFi" },
    { id: 17, name: "Samsung Galaxy Tab S8", category: "tablets", price: 380000, image: "hero img.png", desc: "Snapdragon 8 Gen 1, 128GB" },
    
    // Accessories
    { id: 18, name: "AirPods Pro", category: "accessories", price: 120000, image: "xs.png", desc: "Active noise cancellation" },
    { id: 19, name: "AirPods 3", category: "accessories", price: 85000, image: "xs.png", desc: "Spatial audio, wireless charging" },
    { id: 20, name: "iPhone Charger 20W", category: "accessories", price: 15000, image: "xs.png", desc: "Fast charging adapter" },
    { id: 21, name: "USB-C Cable", category: "accessories", price: 5000, image: "xs.png", desc: "1m braided cable" },
    { id: 22, name: "Phone Case iPhone 13", category: "accessories", price: 8000, image: "xs.png", desc: "Silicone case, various colors" },
    { id: 23, name: "Power Bank 20000mAh", category: "accessories", price: 25000, image: "xs.png", desc: "Fast charging, dual USB" },
    { id: 24, name: "Screen Protector", category: "accessories", price: 3000, image: "xs.png", desc: "Tempered glass, pack of 2" }
];

// Get products by category
function getProductsByCategory(category) {
    if (category === "all") return products;
    return products.filter(p => p.category === category);
}

// Get product by ID
function getProductById(id) {
    return products.find(p => p.id === parseInt(id));
}

// Search products
function searchProducts(query) {
    const term = query.toLowerCase();
    return products.filter(p => 
        p.name.toLowerCase().includes(term) || 
        p.desc.toLowerCase().includes(term)
    );
}
