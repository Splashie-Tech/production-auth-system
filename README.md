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

```

## Start Server

```bash
node server.js
```

## API Endpoints

### Register

POST /api/register

Request Body:
```json
{
  "name": "Jane Doe",
  "email": "jane@example.com",
  "password": "StrongPass1!"
}
```

Password must be at least 8 characters and include an uppercase letter, a number, and a special character.

### Login

POST /api/login

Request Body:
```json
{
  "email": "jane@example.com",
  "password": "StrongPass1!"
}
```

### Refresh Token

POST /api/refresh

Request Body:
```json
{
  "refreshToken": "<refresh-token>"
}
```

### Logout

POST /api/logout

Request Body:
```json
{
  "refreshToken": "<refresh-token>"
}
```

### Forgot Password

POST /api/forgot-password

Request Body:
```json
{
  "email": "jane@example.com"
}
```

### Reset Password

POST /api/reset-password

Request Body:
```json
{
  "token": "<reset-token>",
  "newPassword": "NewStrongPass1!"
}
```

### Admin Route

GET /api/admin

## Token Strategy

Access Token:

* Lifetime: 15 minutes

Refresh Token:

* Lifetime: 7 days

Refresh tokens should be stored inside httpOnly cookies instead of localStorage because JavaScript cannot access httpOnly cookies, reducing XSS attack risks.
