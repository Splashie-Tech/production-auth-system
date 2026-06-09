const express = require("express");

const router = express.Router();

const {
  register,
  login,
  refresh,
  logout,
  forgotPassword,
  resetPassword
} = require("../controllers/authController");

router.post("/register", register);
router.post("/login", login);
router.post("/refresh", refresh);
router.post("/logout", logout);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);


module.exports = router;