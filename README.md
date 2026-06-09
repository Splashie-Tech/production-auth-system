# Production Authentication System

## Features

* User Registration
* User Login
* Access Token Authentication
* Refresh Token Authentication
* Role Based Access Control (RBAC)
* Password Reset
* Logout
* Refresh Token Rotation

## Installation

```bash
npm install
```

## Environment Variables

Create a `.env` file:

```env
PORT=5000

ACCESS_TOKEN_SECRET=your_access_secret

REFRESH_TOKEN_SECRET=your_refresh_secret

RESET_TOKEN_SECRET=your_reset_secret
```

## Start Server

```bash
node server.js
```

## API Endpoints

### Register

POST /api/register

### Login

POST /api/login

### Refresh Token

POST /api/refresh

### Logout

POST /api/logout

### Forgot Password

POST /api/forgot-password

### Reset Password

POST /api/reset-password

### Admin Route

GET /api/admin

## Token Strategy

Access Token:

* Lifetime: 15 minutes

Refresh Token:

* Lifetime: 7 days

Refresh tokens should be stored inside httpOnly cookies instead of localStorage because JavaScript cannot access httpOnly cookies, reducing XSS attack risks.
