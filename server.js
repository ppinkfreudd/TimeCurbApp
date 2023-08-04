require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());


// Replace 'YOUR_MONGODB_URI' with your actual MongoDB connection string
const MONGODB_URI = 'mongodb+srv://rdas:x70KGCOwZXxFuD3e@timecurb.bgup1nl.mongodb.net/?retryWrites=true&w=majority';

// Replace 'YOUR_SECRET_KEY' with your secret key for JWT
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;

const connectDB = async () => {
    try {
      await mongoose.connect(MONGODB_URI, {
       useNewUrlParser: true,
       useUnifiedTopology: true,
       // createIndexes: true,
      });
      console.log('Connected to MongoDB!!!');
    } catch (error) {
      console.error('MongoDB connection error:', error);
    }
  };
  
  connectDB();


const db = mongoose.connection;

db.on('error', (error) => console.error('MongoDB connection error:', error));
db.once('open', () => console.log('Connected to MongoDB'));

const userSchema = new mongoose.Schema({
  _id: { type: String, default: uuidv4 },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  bankAccount: { type: String, default: null },
  charityPreference: { type: String, default: null },
});

const User = mongoose.model('User', userSchema);

app.post('/api/register', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the email is already registered
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered' });
    }

    // Hash the password before saving it to the database
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create a new user object
    const newUser = new User({ email, password: hashedPassword });

    // Save the new user to the database
    await newUser.save();

    return res.status(201).json({ message: 'User registered successfully!' });
  } catch (error) {
    console.error('Error registering user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Find the user by email in the database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Compare the provided password with the hashed password in the database
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate a JWT token for the user
    const token = jwt.sign({ userId: user._id }, JWT_SECRET_KEY, { expiresIn: '1h' });

    return res.json({ token });
  } catch (error) {
    console.error('Error logging in:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/link-bank-account', async (req, res) => {
  const { userId, accountNumber } = req.body;

  try {
    // Find the user in the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Update the user's bank account in the database
    user.bankAccount = accountNumber;
    await user.save();

    return res.json({ message: 'Bank account linked successfully!' });
  } catch (error) {
    console.error('Error linking bank account:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Sample social media usage data (Replace this with actual data from the database)
const socialMediaUsage = {
  instagram: 60, // Time in minutes
  facebook: 45,
  twitter: 30,
};

app.get('/api/social-media-usage/:userId', async (req, res) => {
  const { userId } = req.params;

  try {
    // Find the user in the database
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Return the sample social media usage data
    return res.json(socialMediaUsage);
  } catch (error) {
    console.error('Error fetching social media usage:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// Middleware function to verify JWT token
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Missing token' });
  }

  jwt.verify(token, JWT_SECRET_KEY, (error, user) => {
    if (error) {
      return res.status(403).json({ error: 'Forbidden: Invalid token' });
    }

    req.user = user;
    next();
  });
};

// Example of how to use the authentication middleware to protect routes
app.get('/api/protected-route', authenticateToken, (req, res) => {
  // If the user reaches this route, it means their JWT token is valid
  // You can use req.user.userId to access the user ID
  // Implement your protected route logic here

  return res.json({ message: 'This is a protected route!' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

process.on('SIGINT', async () => {
    try {
      await mongoose.connection.close();
      console.log('MongoDB connection closed. Server shutting down.');
      process.exit(0);
    } catch (error) {
      console.error('Error closing MongoDB connection:', error);
      process.exit(1);
    }
  });
