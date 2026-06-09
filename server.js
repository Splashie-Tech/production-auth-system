const express = require("express");
const app = express();

app.use(express.json());

// routes
const authRoutes = require("./routes/authRoutes");
app.use("/api", authRoutes);

// ONLY START SERVER IF NOT TESTING
if (require.main === module) {
  const PORT = 5000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}

module.exports = app;