# Auth API with Express and TypeScript

## Overview

This project is a simple authentication API built with Express and TypeScript. It implements basic user registration, login functionality, and token-based authentication using JWT (JSON Web Tokens). The API communicates with a MySQL database to store user information and ensures security with bcrypt for password hashing.

## Features

- **User Registration**: Allows users to create a new account by providing their name, email, and password.
- **User Login**: Users can log in using their credentials, and if valid, they receive a JWT for authentication.
- **Protected Route**: A profile route (`/perfil`) is protected, requiring a valid JWT to access.
- **JWT Authentication**: Token-based authentication using JWT to secure routes and ensure proper user validation.

## Technologies Used

- **Express**: Web framework for Node.js.
- **TypeScript**: Superset of JavaScript for static typing and better development experience.
- **JWT (JSON Web Tokens)**: Secure token-based authentication.
- **bcrypt**: Password hashing for secure user authentication.
- **MySQL**: Relational database for storing user information.
- **dotenv**: To manage environment variables (e.g., database credentials, JWT secret).

## Endpoints

- **POST** `/register`: Register a new user.
  - Request body: `{ "nome": "name", "email": "email@example.com", "senha": "password" }`
  
- **POST** `/login`: Login with existing user credentials and receive a JWT token.
  - Request body: `{ "email": "email@example.com", "senha": "password" }`
  
- **GET** `/perfil`: Access the user's profile. Requires a valid JWT in the `Authorization` header.
  - Request header: `Authorization: Bearer <your-token>`
