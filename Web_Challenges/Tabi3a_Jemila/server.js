const express = require("express");
const bodyParser = require("body-parser");
const path = require("path");

const app = express();

app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static("public"));

const flowers = {
  1: {
    title: "The Forbidden Garden",
    content: "Pioneers25{fl0w3rs_bl00m_wh3n_m1ddl3w4r3s_f41l}"
  },
  2: {
    title: "Rose Field",
    content: "Roses symbolize secrecy and hidden messages."
  },
  3: {
    title: "Tulip Valley",
    content: "Tulips once caused one of the first economic bubbles."
  },
  4: {
    title: "Sunflower Plains",
    content: "Sunflowers follow the sun, a behavior called heliotropism."
  },
  5: {
    title: "Daisy Meadow",
    content: "Daisies are often associated with innocence and purity."
  },
  6: {
    title: "Sakura Garden",
    content: "Cherry blossoms represent the fleeting nature of life."
  },
  7: {
    title: "Hibiscus Shore",
    content: "Hibiscus flowers are symbols of delicate beauty."
  },
  8: {
    title: "Lavender Hills",
    content: "Lavender is known for its calming fragrance and uses."
  }
};

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.use("/flower", (req, res, next) => {
  if (req.query.id == "1") {
    return res
      .status(403)
      .send("Access to the Forbidden Garden is restricted 🌱");
  }
  next();
});

app.get("/flower", (req, res) => {
  const id = req.body.id || req.query.id;

  if (!flowers[id]) {
    return res.status(404).send("Flower not found");
  }

  res.json(flowers[id]);
});

app.listen(3999, () => {
  console.log("Tabi3a 🌿 running on http://localhost:3999");
});
