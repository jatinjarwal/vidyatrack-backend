# VidyaTrack Backend

A beginner-friendly Node.js + Express backend for a learning resource tracker app. Built using MongoDB, JWT authentication, and refresh token mechanism.

 Tech Stack
- Node.js
- Express.js
- MongoDB + Mongoose
- JWT Authentication
- bcryptjs for password hashing
- dotenv for env config
- cookie-parser for managing refresh tokens

 Features
- User registration and login with email & password
- JWT-based access token + HTTP-only refresh token
- CRUD operations for learning resources (title, link, notes, category)
- Protected routes

 Folder Structure
 vidyatrack-backend/
├── models/
├── middleware/
├── server.js
├── .env
├── .gitignore
