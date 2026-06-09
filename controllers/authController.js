const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const users = require("../models/User");

// Authentication controller manages user registration, login, token refresh,
// logout, and password reset flows.

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

// Register a new user and store hashed credentials.
const register = async (req, res) => {

  const { name, email, password } = req.body;

  // Verify required registration fields are present
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

  // Prevent duplicate email registrations
  const existingUser = users.find(
    user => user.email === email
  );

  if (existingUser) {
    return res.status(409).json({
      message: "User already exists"
    });
  }

  // Hash password before storing it
  const hashedPassword =
    await bcrypt.hash(password, 10);

  const user = {
  id: Date.now(),
  name,
  email,
  password: hashedPassword,
  role: "user", // Default role for testing
  refreshToken: null
};

  users.push(user);

  return res.status(201).json({
    message: "User registered successfully"
  });

};

// Authenticate a user and issue access + refresh tokens.
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

// Refresh the access token using a valid refresh token.
const refresh = (req, res) => {

  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(401).json({
      message: "Refresh token required"
    });
  }

  // Find user by stored refresh token
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

    // Issue a new access token and persist the new refresh token
    const newAccessToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: "15m" }
    );

    const newRefreshToken = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: "7d" }
    );

    user.refreshToken = newRefreshToken;

    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken
    });

  } catch (err) {
    return res.status(403).json({
      message: "Token expired or invalid"
    });
  }
};

// Logout by invalidating the stored refresh token.
const logout = (req, res) => {

  const { refreshToken } = req.body;

  const user = users.find(
    u => u.refreshToken === refreshToken
  );

  if (user) {
    user.refreshToken = null;
  }

  return res.json({
    message: "Logged out successfully"
  });
};

// Generate a password reset token for a user and expire it after 15 minutes.
const forgotPassword = (req, res) => {

  const { email } = req.body;

  // Locate the user account by email
  const user =
    users.find(u => u.email === email);

  if (!user) {

    return res.status(404).json({
      message: "User not found"
    });

  }

  const resetToken =
    crypto.randomBytes(32).toString("hex");

  user.resetToken = resetToken;

  user.resetTokenExpiry =
    Date.now() + 15 * 60 * 1000;

  return res.json({
    resetToken
  });

};

// Reset the user's password when the reset token is valid.
const resetPassword = async (req, res) => {

  const { token, newPassword } = req.body;

  // Find user with matching token and ensure token hasn't expired
  const user = users.find(
    u =>
      u.resetToken === token &&
      u.resetTokenExpiry > Date.now()
  );

  if (!user) {

    return res.status(400).json({
      message: "Invalid or expired token"
    });

  }

  user.password =
    await bcrypt.hash(newPassword, 10);

  user.resetToken = null;
  user.resetTokenExpiry = null;

  return res.json({
    message: "Password reset successful"
  });

};

module.exports = {
  register,
  login,
  refresh,
  logout,
  forgotPassword,
  resetPassword
};
