// Index Page JavaScript
const API_BASE = "";
let featuredProducts = [];

// Load featured products from API
async function loadFeaturedProducts() {
  console.log("Loading featured products...");

  try {
    console.log("Fetching from API...");
    const response = await fetch(`${API_BASE}/api/products`);
    console.log("API response status:", response.status);

    if (!response.ok) {
      throw new Error("API request failed");
    }

    const products = await response.json();
    console.log("Products from API:", products);

    featuredProducts = products.slice(0, 6);
    renderFeaturedProducts();
  } catch (error) {
    console.error("Error loading products:", error);

    // Try localStorage fallback
    const stored = localStorage.getItem("dondad_products");
    console.log("LocalStorage products:", stored);

    if (stored) {
      featuredProducts = JSON.parse(stored).slice(0, 6);
    } else if (typeof products !== "undefined") {
      // Check if products.js is loaded
      featuredProducts = products.slice(0, 6);
      console.log("Using products.js fallback:", featuredProducts);
    } else {
      console.log("No products found anywhere");
      featuredProducts = [];
    }
    renderFeaturedProducts();
  }
}

// Render featured products
function renderFeaturedProducts() {
  const container = document.getElementById("featured-products");
  console.log("Container found:", !!container);
  console.log("Featured products to render:", featuredProducts);

  if (!container) return;

  if (featuredProducts.length === 0) {
    container.innerHTML =
      '<p style="text-align:center; padding: 2rem; color: var(--text-muted);">No featured products available</p>';
    return;
  }

  container.innerHTML = featuredProducts
    .map(
      (p) => `
        <article class="featured-card">
            <img src="${p.image}" alt="${p.name}" onerror="this.src='logo.png'">
            <h3>${p.name}</h3>
            <p class="desc">${p.desc || ""}</p>
            <p class="price">₦${p.price.toLocaleString()}</p>
            <a href="product.html?id=${p.id}" class="btn">View Details</a>
        </article>
    `,
    )
    .join("");

  console.log("Rendered HTML:", container.innerHTML.length, "characters");
}

// Load featured products on page load
document.addEventListener("DOMContentLoaded", function () {
  loadFeaturedProducts();
});
