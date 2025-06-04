// server.js
const express = require('express');
const mongoose = require('mongoose');
const multer = require('multer');
const path = require('path');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static('uploads'));

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/userDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  phone: { type: String, required: true },
  gender: { type: String, enum: ['Male', 'Female', 'Other'], required: true },
  panNo: { type: String, required: true },
  panDoc: { type: String, required: true },
  aadharNo: { type: String, required: true },
  aadharDoc: { type: String, required: true },
  permanentAddress: {
    street: String,
    city: String,
    state: String,
    pinCode: String
  },
  temporaryAddress: {
    street: String,
    city: String,
    state: String,
    pinCode: String
  },
  dob: { type: Date, required: true }
});

// Virtual for age calculation
userSchema.virtual('age').get(function() {
  const today = new Date();
  const birthDate = new Date(this.dob);
  let age = today.getFullYear() - birthDate.getFullYear();
  const monthDiff = today.getMonth() - birthDate.getMonth();
  if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
});

const User = mongoose.model('User', userSchema);

// File Upload Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${file.originalname}`);
  }
});

const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

// Routes
app.post('/api/users', upload.fields([
  { name: 'panDoc', maxCount: 1 },
  { name: 'aadharDoc', maxCount: 1 }
]), async (req, res) => {
  try {
    const { files, body } = req;
    
    const userData = {
      ...body,
      panDoc: files.panDoc[0].path,
      aadharDoc: files.aadharDoc[0].path,
      dob: new Date(body.dob)
    };

    const user = new User(userData);
    await user.save();
    
    res.status(201).json(user);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await User.find().select('-__v');
    res.json(users);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create uploads directory if not exists
const fs = require('fs');
if (!fs.existsSync('uploads')) {
  fs.mkdirSync('uploads');
}

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port http://localhost:${PORT}`);
});