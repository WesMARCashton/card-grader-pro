# CardGrade Pro 🎴

AI-Powered PSA-Style Collectible Card Grading App

## Features

- **User Authentication** - Sign up and login with secure JWT tokens
- **Card Upload** - Upload front and back images of your cards
- **AI Grading** - Powered by Google's Gemini AI for accurate PSA-style grading
- **Detailed Breakdown** - Get scores for Centering, Corners, Edges, Surface, and Print Quality
- **PSA Equivalent** - See how your card would grade on the PSA scale (1-10)
- **Market Notes** - Get insights on card collectibility and significance

## Supported Cards

- Sports Cards: NHL, NFL, NBA, MLB
- Trading Cards: Pokemon, Magic: The Gathering, Yu-Gi-Oh
- And many more!

## Setup Instructions

### 1. Install Dependencies

```bash
cd card-grader-app
npm install
```

### 2. Configure Environment

The `.env` file is already configured with your Gemini API key. For production, you should:

1. Generate a new API key at [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Change the `JWT_SECRET` to a secure random string
3. Never commit the `.env` file to version control

### 3. Start the Server

```bash
npm start
```

The app will be available at: **http://localhost:3000**

## Demo Account

- **Email:** demo@cardgrader.com
- **Password:** demo123

## API Endpoints

### Authentication

- `POST /api/auth/signup` - Create new account
- `POST /api/auth/login` - Login to existing account
- `GET /api/auth/me` - Get current user info

### Grading

- `POST /api/grade` - Grade a card (multipart form with frontImage and optional backImage)
- `GET /api/history` - Get user's grading history

## Tech Stack

- **Backend:** Node.js, Express
- **Frontend:** Vanilla HTML, CSS, JavaScript
- **AI:** Google Gemini 1.5 Flash
- **Auth:** JWT (JSON Web Tokens)

## Project Structure

```
card-grader-app/
├── server/
│   └── index.js          # Express server & API routes
├── client/
│   └── public/
│       └── index.html    # Frontend application
├── package.json
├── .env                  # Environment variables
└── README.md
```

## Production Considerations

For production deployment:

1. Use a proper database (PostgreSQL, MongoDB) instead of in-memory storage
2. Add rate limiting to prevent API abuse
3. Implement proper error logging
4. Use HTTPS
5. Store API keys securely (use environment variables, not hardcoded)
6. Add input validation and sanitization
7. Implement password reset functionality

## License

MIT
