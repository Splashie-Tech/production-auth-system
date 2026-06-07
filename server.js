require("dotenv").config();
const express = require("express");

const app = express();

app.use(express.json());

const authRoutes =
  require("./routes/authRoutes");

app.use("/api", authRoutes);

const PORT = 5000;

app.listen(PORT, () => {
  console.log(
    `Server running on port ${PORT}`
  );
});