require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, '../client/public')));

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// In-memory user storage (use a database in production)
const users = new Map();

// Add demo user
users.set('demo@cardgrader.com', {
  email: 'demo@cardgrader.com',
  password: bcrypt.hashSync('demo123', 10),
  name: 'Demo User',
  gradingHistory: []
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    if (users.has(email)) {
      return res.status(400).json({ error: 'An account with this email already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.set(email, {
      email,
      password: hashedPassword,
      name,
      gradingHistory: []
    });

    const token = jwt.sign({ email, name }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { email, name } });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = users.get(email);
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ email, name: user.name }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ token, user: { email, name: user.name } });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json({ email: user.email, name: user.name });
});

// Card Grading Route
app.post('/api/grade', authenticateToken, upload.fields([
  { name: 'frontImage', maxCount: 1 },
  { name: 'backImage', maxCount: 1 }
]), async (req, res) => {
  try {
    const frontFile = req.files['frontImage']?.[0];
    const backFile = req.files['backImage']?.[0];

    if (!frontFile) {
      return res.status(400).json({ error: 'Front image is required' });
    }

    const frontBase64 = frontFile.buffer.toString('base64');
    const backBase64 = backFile ? backFile.buffer.toString('base64') : null;

    // Call Gemini API
    const result = await gradeCardWithGemini(frontBase64, backBase64);
    
    // Save to user's history
    const user = users.get(req.user.email);
    if (user) {
      user.gradingHistory.unshift({
        id: Date.now(),
        timestamp: new Date().toISOString(),
        result
      });
      // Keep only last 20 gradings
      user.gradingHistory = user.gradingHistory.slice(0, 20);
    }

    res.json(result);
  } catch (error) {
    console.error('Grading error:', error);
    res.status(500).json({ error: error.message || 'Failed to grade card' });
  }
});

// Get grading history
app.get('/api/history', authenticateToken, (req, res) => {
  const user = users.get(req.user.email);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  res.json(user.gradingHistory || []);
});

// Gemini API Integration
async function gradeCardWithGemini(frontBase64, backBase64) {
  const systemPrompt = `You are an expert collectible card grader with decades of experience grading sports cards (NHL, NFL, NBA, MLB) and trading cards (Pokemon, Magic: The Gathering, Yu-Gi-Oh, etc.). You grade cards following PSA (Professional Sports Authenticator) standards meticulously.

GRADING SCALE (1-10):
- 10 Gem Mint: Perfect condition. Four perfectly sharp corners. Sharp focus. Full original gloss. Free of staining. No print defects. 55/45 centering or better on front, 75/25 or better on back.
- 9 Mint: One minor flaw. Corners sharp to naked eye. 60/40 centering or better on front, 90/10 or better on back.
- 8 NM-MT: Minor flaw on corner or edges. 65/35 centering or better on front.
- 7 Near Mint: Slight surface wear. 70/30 centering or better on front.
- 6 EX-MT: Visible surface wear or print spots. 75/25 centering or better.
- 5 Excellent: Moderate wear on surface. Corners slightly rounded.
- 4 VG-EX: Noticeable wear, minor creases, light scuffing.
- 3 Very Good: Heavy wear, major creasing, rounded corners.
- 2 Good: Significant damage, heavy creases, major scuffing.
- 1 Poor: Extensive damage, missing pieces, tears, or holes.

Analyze the provided card image(s) and provide a detailed grading report.

IMPORTANT: Return ONLY valid JSON in this exact format, no markdown code blocks or other text:
{
  "cardIdentification": {
    "sport": "string (NHL/NFL/NBA/MLB/Pokemon/MTG/Yu-Gi-Oh/Other)",
    "playerOrCharacter": "string",
    "cardSet": "string",
    "year": "string or null",
    "cardNumber": "string or null"
  },
  "grades": {
    "centering": {
      "score": number (1-10, can use .5),
      "frontRatio": "string like 55/45",
      "backRatio": "string like 60/40 or null if no back image",
      "notes": "string explaining centering assessment"
    },
    "corners": {
      "score": number (1-10, can use .5),
      "notes": "string detailing each corner condition"
    },
    "edges": {
      "score": number (1-10, can use .5),
      "notes": "string describing edge wear and chipping"
    },
    "surface": {
      "score": number (1-10, can use .5),
      "notes": "string about scratches, print defects, gloss"
    },
    "printQuality": {
      "score": number (1-10, can use .5),
      "notes": "string about focus, color registration, print defects"
    }
  },
  "overallGrade": number (1-10, can use .5),
  "psaEquivalent": "string like PSA 8 or PSA 9",
  "summary": "string with comprehensive 2-3 paragraph assessment explaining the grade and any notable features or defects",
  "marketNotes": "string with brief comment on card significance or collectibility if recognizable"
}`;

  const parts = [
    { text: systemPrompt },
    { text: "Please grade this collectible card following PSA standards. Analyze every detail carefully. Here is the front of the card:" },
    {
      inline_data: {
        mime_type: "image/jpeg",
        data: frontBase64
      }
    }
  ];

  if (backBase64) {
    parts.push(
      { text: "Here is the back of the card:" },
      {
        inline_data: {
          mime_type: "image/jpeg",
          data: backBase64
        }
      }
    );
  } else {
    parts.push({ text: "No back image was provided. Please grade based on the front only and note that centering back ratio cannot be assessed." });
  }

  const response = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts }],
        generationConfig: {
          temperature: 0.4,
          topK: 32,
          topP: 1,
          maxOutputTokens: 4096,
        }
      })
    }
  );

  const data = await response.json();

  if (data.error) {
    throw new Error(data.error.message || 'Gemini API request failed');
  }

  const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';

  // Parse JSON from response
  let jsonText = text;
  const codeBlockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (codeBlockMatch) {
    jsonText = codeBlockMatch[1];
  }

  const jsonMatch = jsonText.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error('Could not parse grading response from AI');
  }

  return JSON.parse(jsonMatch[0]);
}

// Serve the frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/public/index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🎴 CardGrade Pro server running on http://localhost:${PORT}`);
});
