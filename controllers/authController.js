const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const users = require("../models/User");

// Email validation regex
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// Password validation: minimum 8 chars, 1 uppercase, 1 number, 1 special char
const validatePassword = (password) => {
  const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return passwordRegex.test(password);
};

// Email validation
const validateEmail = (email) => {
  return emailRegex.test(email);
};

const register = async (req, res) => {

  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "All fields are required"
    });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({
      message: "Invalid email format"
    });
  }

  if (!validatePassword(password)) {
    return res.status(400).json({
      message: "Password must be at least 8 characters with 1 uppercase letter, 1 number, and 1 special character (@$!%*?&)"
    });
  }

  const existingUser = users.find(
    user => user.email === email
  );

  if (existingUser) {
    return res.status(409).json({
      message: "User already exists"
    });
  }

  const hashedPassword =
    await bcrypt.hash(password, 10);

  const user = {
  id: Date.now(),
  name,
  email,
  password: hashedPassword,
  role: "user",
  refreshToken: null
};

  users.push(user);

  return res.status(201).json({
    message: "User registered successfully"
  });

};

const login = async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      message: "Email and password are required"
    });
  }

  if (!validateEmail(email)) {
    return res.status(400).json({
      message: "Invalid email format"
    });
  }

  const user = users.find(
    user => user.email === email
  );

  if (!user) {
    return res.status(404).json({
      message: "User not found"
    });
  }

  const isMatch = await bcrypt.compare(password, user.password);

  if (!isMatch) {
    return res.status(401).json({
      message: "Invalid credentials"
    });
  }

  const accessToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: "15m" }
  );

  const refreshToken = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: "7d" }
  );

  user.refreshToken = refreshToken;

  return res.status(200).json({
    message: "Login successful",
    accessToken,
    refreshToken
  });

};

const refresh = (req, res) => {

  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token required"
    });
  }

  const user = users.find(
    u => u.refreshToken === refreshToken
  );

  if (!user) {
    return res.status(403).json({
      message: "Invalid refresh token"
    });
  }

  try {
    const decoded = jwt.verify(
      refreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const newAccessToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    return res.json({
      accessToken: newAccessToken
    });

  } catch (err) {
    return res.status(403).json({
      message: "Token expired or invalid"
    });
  }
};

module.exports = {
  register,
  login,
  refresh
};
