// Index Page JavaScript
const API_BASE = "";

// Load featured products
async function loadFeaturedProducts() {
  const container = document.getElementById("featured-products");
  if (!container) return;

  try {
    const response = await fetch(`${API_BASE}/api/featured`);
    const products = await response.json();
    const featured = products.slice(0, 6);
    renderFeaturedProducts(featured);
  } catch (error) {
    // Fallback to local products
    const featured = (typeof products !== 'undefined' ? products : []).slice(0, 6);
    renderFeaturedProducts(featured);
  }
}

// Render featured products
function renderFeaturedProducts(products) {
  const container = document.getElementById("featured-products");
  if (!container) return;

  if (products.length === 0) {
    container.innerHTML = '<p style="text-align:center; padding: 2rem;">No products available</p>';
    return;
  }

  container.innerHTML = products
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
}

// Load on page load
document.addEventListener("DOMContentLoaded", function () {
  loadFeaturedProducts();
});
