const flowers = [
  { id: 2, name: "🌹 Rose Field" },
  { id: 3, name: "🌷 Tulip Valley" },
  { id: 4, name: "🌻 Sunflower Plains" },

  // dummy flowers
  { id: 5, name: "🌼 Daisy Meadow" },
  { id: 6, name: "🌸 Sakura Garden" },
  { id: 7, name: "🌺 Hibiscus Shore" },
  { id: 8, name: "🌾 Lavender Hills" }
];

const container = document.getElementById("flowers");

flowers.forEach(f => {
  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `<h3>${f.name}</h3>`;

  card.onclick = async () => {
    try {
      const res = await fetch(`/flower?id=${f.id}`);
      const data = await res.json();

      document.getElementById("title").innerText = data.title;
      document.getElementById("content").innerText = data.content;
      document.getElementById("viewer").style.display = "block";
    } catch {
      document.getElementById("title").innerText = "Unavailable";
      document.getElementById("content").innerText = "This region cannot be accessed.";
      document.getElementById("viewer").style.display = "block";
    }
  };

  container.appendChild(card);
});
