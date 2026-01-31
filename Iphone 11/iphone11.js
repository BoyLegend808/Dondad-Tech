

function displayPhones(phoneList) {
  gridContainer.innerHTML = "";


  phoneList.forEach((phone) => {

    card.innerHTML = `
            <div class="image-container">
                <img src="${phone.image}" alt="${phone.name}">
            </div>
            <h3 class="phone-name">${phone.name}</h3>
            <p class="phone-desc">${phone.description}</p>
        `;

    card.addEventListener("click", () => {
      if (phone.id === 1) {
        window.location.href = "iphone11.html";
      }
      else {
        alert("Product page for " + phone.name + " is under construction!");
      }
    });
    gridContainer.appendChild(card);
  });
}
