// Phone data
const phones = [
    { name: "iPhone 11", image: "Iphone 11/iphone_113-removebg-preview.png", desc: "Triple-camera, A13 chip", link: "Iphone 11/iphone11.html" },
    { name: "iPhone XS", image: "xs.png", desc: "Super Retina OLED", link: "#" },
    { name: "iPhone XR", image: "https://via.placeholder.com/150x250/38bdf8/FFFFFF?text=iPhone+XR", desc: "Liquid Retina, Face ID", link: "#" },
    { name: "iPhone X", image: "https://via.placeholder.com/150x250/555555/FFFFFF?text=iPhone+X", desc: "First OLED iPhone", link: "#" },
    { name: "iPhone SE", image: "https://via.placeholder.com/150x250/ef4444/FFFFFF?text=iPhone+SE", desc: "Classic design", link: "#" },
    { name: "iPhone 7 Plus", image: "https://via.placeholder.com/150x250/cccccc/000000?text=iPhone+7+", desc: "Dual camera", link: "#" },
    { name: "iPhone 7", image: "https://via.placeholder.com/150x250/999999/000000?text=iPhone+7", desc: "A10 Fusion", link: "#" },
    { name: "iPhone 6s", image: "https://via.placeholder.com/150x250/eeeeee/000000?text=iPhone+6s", desc: "3D Touch", link: "#" }
];

// Display phones
const grid = document.getElementById("phoneGrid");
const search = document.getElementById("searchInput");
const noResults = document.getElementById("noResults");

function showPhones(list) {
    grid.innerHTML = "";
    if (list.length === 0) {
        noResults.hidden = false;
        return;
    }
    noResults.hidden = true;
    list.forEach(phone => {
        const card = document.createElement("div");
        card.className = "phone-card";
        card.innerHTML = `<img src="${phone.image}" alt="${phone.name}"><h3>${phone.name}</h3><p>${phone.desc}</p>`;
        card.onclick = () => phone.link === "#" ? alert("Coming soon!") : (window.location.href = phone.link);
        grid.appendChild(card);
    });
}

// Search filter
search.onkeyup = (e) => {
    const term = e.target.value.toLowerCase();
    const filtered = phones.filter(p => p.name.toLowerCase().includes(term));
    showPhones(filtered);
};

// Hamburger menu
const hamburger = document.querySelector(".hamburger");
const navLinks = document.querySelector(".nav-links");

hamburger.onclick = () => {
    hamburger.classList.toggle("active");
    navLinks.classList.toggle("active");
};

// Close menu on link click
navLinks.querySelectorAll("a").forEach(link => {
    link.onclick = () => {
        hamburger.classList.remove("active");
        navLinks.classList.remove("active");
    };
});

// Initial load
showPhones(phones);
