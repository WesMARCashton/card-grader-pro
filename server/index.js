require('dotenv').config();
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');
const { MongoClient, ObjectId } = require('mongodb');

const app = express();
const PORT = process.env.PORT || 3000;

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI;
const RESEND_API_KEY = process.env.RESEND_API_KEY;
const APP_URL = process.env.APP_URL || 'https://card-grader-pro-production.up.railway.app';

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI environment variable is required');
  process.exit(1);
}

let db;
let usersCollection;
let cardsCollection;

async function connectToMongoDB() {
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db('cardgrader');
    usersCollection = db.collection('users');
    cardsCollection = db.collection('cards');
    
    // Create indexes
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    await usersCollection.createIndex({ verificationToken: 1 });
    await cardsCollection.createIndex({ userEmail: 1 });
    
    console.log('✅ Connected to MongoDB');
    
    // Create admin user if doesn't exist
    const adminExists = await usersCollection.findOne({ email: 'admin@cardgrader.com' });
    if (!adminExists) {
      await usersCollection.insertOne({
        email: 'admin@cardgrader.com',
        password: await bcrypt.hash('admin123', 10),
        name: 'Admin',
        isAdmin: true,
        isVerified: true,
        createdAt: new Date()
      });
      console.log('✅ Admin user created: admin@cardgrader.com / admin123');
    }
    
    // Create demo user if doesn't exist
    const demoExists = await usersCollection.findOne({ email: 'demo@cardgrader.com' });
    if (!demoExists) {
      await usersCollection.insertOne({
        email: 'demo@cardgrader.com',
        password: await bcrypt.hash('demo123', 10),
        name: 'Demo User',
        isAdmin: false,
        isVerified: true,
        createdAt: new Date()
      });
      console.log('✅ Demo user created: demo@cardgrader.com / demo123');
    }
    
  } catch (error) {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
  }
}

// Send verification email using Resend
async function sendVerificationEmail(email, name, token) {
  if (!RESEND_API_KEY) {
    console.log('⚠️ RESEND_API_KEY not set, skipping email verification');
    return false;
  }

  const verificationUrl = `${APP_URL}/verify?token=${token}`;
  
  try {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'CardGrade Pro <onboarding@resend.dev>',
        to: email,
        subject: 'Verify your CardGrade Pro account',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <style>
              body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
              .container { max-width: 600px; margin: 0 auto; padding: 20px; }
              .header { text-align: center; padding: 20px 0; }
              .logo { font-size: 48px; }
              h1 { color: #7c3aed; margin: 0; }
              .button { 
                display: inline-block; 
                background: linear-gradient(135deg, #a855f7 0%, #ec4899 100%);
                color: white !important; 
                padding: 14px 32px; 
                text-decoration: none; 
                border-radius: 8px;
                font-weight: bold;
                margin: 20px 0;
              }
              .footer { margin-top: 30px; font-size: 12px; color: #666; text-align: center; }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="header">
                <div class="logo">🎴</div>
                <h1>CardGrade Pro</h1>
              </div>
              
              <p>Hi ${name},</p>
              
              <p>Welcome to CardGrade Pro! Please verify your email address to complete your registration and start grading cards.</p>
              
              <p style="text-align: center;">
                <a href="${verificationUrl}" class="button">Verify Email Address</a>
              </p>
              
              <p>Or copy and paste this link into your browser:</p>
              <p style="word-break: break-all; color: #7c3aed;">${verificationUrl}</p>
              
              <p>This link will expire in 24 hours.</p>
              
              <div class="footer">
                <p>If you didn't create an account with CardGrade Pro, you can safely ignore this email.</p>
                <p>© 2024 CardGrade Pro. AI-Powered Card Grading.</p>
              </div>
            </div>
          </body>
          </html>
        `
      })
    });

    const data = await response.json();
    
    if (response.ok) {
      console.log('✅ Verification email sent to:', email);
      return true;
    } else {
      console.error('❌ Failed to send email:', data);
      return false;
    }
  } catch (error) {
    console.error('❌ Email send error:', error);
    return false;
  }
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(express.static(path.join(__dirname, '../client/public')));

// Configure multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 }
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'cardgrader-secret-key-2024', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Admin Middleware
const requireAdmin = async (req, res, next) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user || !user.isAdmin) {
      return res.status(403).json({ error: 'Admin access required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
};

// ============ AUTH ROUTES ============

app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user exists
    const existingUser = await usersCollection.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      return res.status(400).json({ error: 'An account with this email already exists' });
    }

    // Generate verification token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    // Create user
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
      email: email.toLowerCase(),
      password: hashedPassword,
      name,
      isAdmin: false,
      isVerified: false,
      verificationToken,
      verificationTokenExpiry: tokenExpiry,
      createdAt: new Date()
    };
    
    await usersCollection.insertOne(newUser);

    // Send verification email
    const emailSent = await sendVerificationEmail(email.toLowerCase(), name, verificationToken);

    if (emailSent) {
      res.json({ 
        success: true, 
        message: 'Account created! Please check your email to verify your account.',
        requiresVerification: true
      });
    } else {
      // If email fails, still create account but mark as verified (fallback)
      await usersCollection.updateOne(
        { email: email.toLowerCase() },
        { $set: { isVerified: true } }
      );
      
      const token = jwt.sign(
        { email: newUser.email, name: newUser.name },
        process.env.JWT_SECRET || 'cardgrader-secret-key-2024',
        { expiresIn: '7d' }
      );
      
      res.json({ token, user: { email: newUser.email, name: newUser.name } });
    }
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Email verification endpoint
app.get('/api/auth/verify', async (req, res) => {
  try {
    const { token } = req.query;

    if (!token) {
      return res.status(400).json({ error: 'Verification token is required' });
    }

    const user = await usersCollection.findOne({ 
      verificationToken: token,
      verificationTokenExpiry: { $gt: new Date() }
    });

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification link' });
    }

    // Mark user as verified
    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { isVerified: true },
        $unset: { verificationToken: '', verificationTokenExpiry: '' }
      }
    );

    res.json({ success: true, message: 'Email verified successfully! You can now sign in.' });
  } catch (error) {
    console.error('Verification error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Resend verification email
app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    const user = await usersCollection.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return res.status(404).json({ error: 'No account found with this email' });
    }

    if (user.isVerified) {
      return res.status(400).json({ error: 'This account is already verified' });
    }

    // Generate new token
    const verificationToken = crypto.randomBytes(32).toString('hex');
    const tokenExpiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    await usersCollection.updateOne(
      { _id: user._id },
      { 
        $set: { 
          verificationToken,
          verificationTokenExpiry: tokenExpiry
        }
      }
    );

    const emailSent = await sendVerificationEmail(user.email, user.name, verificationToken);

    if (emailSent) {
      res.json({ success: true, message: 'Verification email sent! Please check your inbox.' });
    } else {
      res.status(500).json({ error: 'Failed to send verification email. Please try again.' });
    }
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const user = await usersCollection.findOne({ email: email.toLowerCase() });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Check if email is verified
    if (!user.isVerified) {
      return res.status(403).json({ 
        error: 'Please verify your email before signing in',
        requiresVerification: true,
        email: user.email
      });
    }

    const token = jwt.sign(
      { email: user.email, name: user.name, isAdmin: user.isAdmin },
      process.env.JWT_SECRET || 'cardgrader-secret-key-2024',
      { expiresIn: '7d' }
    );

    res.json({ 
      token, 
      user: { email: user.email, name: user.name, isAdmin: user.isAdmin } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await usersCollection.findOne({ email: req.user.email });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json({ email: user.email, name: user.name, isAdmin: user.isAdmin });
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Verification page redirect
app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/public/verify.html'));
});

// ============ CARD GRADING ROUTE ============

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
    
    // Add image data to result
    result.frontImage = frontBase64;
    result.backImage = backBase64;

    res.json(result);
  } catch (error) {
    console.error('Grading error:', error);
    res.status(500).json({ error: error.message || 'Failed to grade card' });
  }
});

// ============ COLLECTION ROUTES ============

app.post('/api/collection', authenticateToken, async (req, res) => {
  try {
    const { card } = req.body;
    
    if (!card) {
      return res.status(400).json({ error: 'Card data is required' });
    }

    const savedCard = {
      userEmail: req.user.email,
      userName: req.user.name,
      savedAt: new Date(),
      ...card
    };

    const result = await cardsCollection.insertOne(savedCard);
    savedCard._id = result.insertedId;

    res.json({ success: true, card: savedCard });
  } catch (error) {
    console.error('Save to collection error:', error);
    res.status(500).json({ error: 'Failed to save card' });
  }
});

app.get('/api/collection', authenticateToken, async (req, res) => {
  try {
    const cards = await cardsCollection
      .find({ userEmail: req.user.email })
      .sort({ savedAt: -1 })
      .toArray();
    
    // Transform _id to id for frontend compatibility
    const transformedCards = cards.map(card => ({
      ...card,
      id: card._id.toString()
    }));
    
    res.json(transformedCards);
  } catch (error) {
    console.error('Get collection error:', error);
    res.status(500).json({ error: 'Failed to get collection' });
  }
});

app.delete('/api/collection/:id', authenticateToken, async (req, res) => {
  try {
    const cardId = req.params.id;
    
    const result = await cardsCollection.deleteOne({
      _id: new ObjectId(cardId),
      userEmail: req.user.email
    });

    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }

    res.json({ success: true });
  } catch (error) {
    console.error('Delete from collection error:', error);
    res.status(500).json({ error: 'Failed to delete card' });
  }
});

// ============ ADMIN ROUTES ============

app.get('/api/admin/stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const totalUsers = await usersCollection.countDocuments();
    const verifiedUsers = await usersCollection.countDocuments({ isVerified: true });
    const totalCards = await cardsCollection.countDocuments();
    
    // Users created in last 7 days
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    const newUsersThisWeek = await usersCollection.countDocuments({
      createdAt: { $gte: weekAgo }
    });
    
    // Cards graded in last 7 days
    const cardsThisWeek = await cardsCollection.countDocuments({
      savedAt: { $gte: weekAgo }
    });
    
    // Average grade
    const gradeStats = await cardsCollection.aggregate([
      { $group: { _id: null, avgGrade: { $avg: '$overallGrade' } } }
    ]).toArray();
    const avgGrade = gradeStats[0]?.avgGrade?.toFixed(1) || 0;
    
    // Top users by card count
    const topUsers = await cardsCollection.aggregate([
      { $group: { _id: '$userEmail', count: { $sum: 1 }, name: { $first: '$userName' } } },
      { $sort: { count: -1 } },
      { $limit: 5 }
    ]).toArray();

    res.json({
      totalUsers,
      verifiedUsers,
      totalCards,
      newUsersThisWeek,
      cardsThisWeek,
      avgGrade,
      topUsers
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

app.get('/api/admin/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const users = await usersCollection
      .find({}, { projection: { password: 0, verificationToken: 0 } })
      .sort({ createdAt: -1 })
      .toArray();
    
    // Get card count for each user
    const usersWithCardCount = await Promise.all(users.map(async (user) => {
      const cardCount = await cardsCollection.countDocuments({ userEmail: user.email });
      return { ...user, cardCount };
    }));
    
    res.json(usersWithCardCount);
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to get users' });
  }
});

app.delete('/api/admin/users/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    
    // Get user email first
    const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Don't allow deleting admin
    if (user.isAdmin) {
      return res.status(400).json({ error: 'Cannot delete admin user' });
    }
    
    // Delete user's cards
    await cardsCollection.deleteMany({ userEmail: user.email });
    
    // Delete user
    await usersCollection.deleteOne({ _id: new ObjectId(userId) });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

app.get('/api/admin/cards', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const cards = await cardsCollection
      .find({})
      .sort({ savedAt: -1 })
      .limit(100)
      .toArray();
    
    const transformedCards = cards.map(card => ({
      ...card,
      id: card._id.toString()
    }));
    
    res.json(transformedCards);
  } catch (error) {
    console.error('Get all cards error:', error);
    res.status(500).json({ error: 'Failed to get cards' });
  }
});

app.delete('/api/admin/cards/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const cardId = req.params.id;
    
    const result = await cardsCollection.deleteOne({ _id: new ObjectId(cardId) });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Admin delete card error:', error);
    res.status(500).json({ error: 'Failed to delete card' });
  }
});

// ============ GEMINI API INTEGRATION ============

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
          temperature: 0.1,
          topK: 1,
          topP: 0.95,
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

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/public/admin.html'));
});

// Serve the frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../client/public/index.html'));
});

// Start server
connectToMongoDB().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🎴 CardGrade Pro server running on http://localhost:${PORT}`);
  });
});
