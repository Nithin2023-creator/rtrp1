const express = require('express');
const mongoose = require('mongoose');

const path = require('path');
const cors = require('cors');
const fs = require('fs');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use('/certificates', express.static('certificates'));
const multer = require('multer');

// MongoDB Connection
mongoose.connect('mongodb://127.0.0.1:27017/educationDB', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// Education Schema
const educationSchema = new mongoose.Schema({
  board: { type: String, required: true },
  schoolName: { type: String, required: true },
  percentage: { type: Number, required: true },
  city: { type: String, required: true },
  state: { type: String, required: true },
  fromYear: { type: Number, required: true },
  toYear: { type: Number, required: true },
  certificate: { type: String, required: true }
});

const Education = mongoose.model('Education', educationSchema);


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
      // Check file field name to determine the destination folder
      if (file.fieldname === 'up') {
        cb(null, 'up/');
      } else if (file.fieldname === 'certificates') {
        cb(null, 'certificates/');
      }
      else if(file.filename==='documents'){
        cb(null,'documents/');
      }
       else {
        cb(new Error('Invalid destination'), false);
      }
    },
    filename: (req, file, cb) => {
      cb(null, `${Date.now()}-${file.originalname}`);
    }
  });
  
  const upload = multer({
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
      if (file.mimetype === 'application/pdf' || 
          file.mimetype === 'image/jpeg' || 
          file.mimetype === 'image/png') {
        cb(null, true);
      } else {
        cb(new Error('Invalid file type'), false);
      }
    }
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
  

// UG Schema
const ugSchema = new mongoose.Schema({
    universityName: { type: String, required: true },
    collegeName: { type: String, required: true },
    specialization: { type: String, required: true },
    degree: { type: String, required: true },
    course: { type: String, required: true },
    percentage: { type: Number, required: true },
    document: { type: String, required: true },
    admissionYear: { type: Number, required: true },
    graduationYear: { type: Number, required: true }
  });
  
  const UG = mongoose.model('UG', ugSchema);
  
  // Routes
app.post('/api/ug', upload.single('document'), async (req, res) => {
    try {
      const { body, file } = req;
      
      const ugData = {
        ...body,
        percentage: parseFloat(body.percentage),
        admissionYear: parseInt(body.admissionYear),
        graduationYear: parseInt(body.graduationYear),
        document: file.path
      };
  
      const ugRecord = new UG(ugData);
      await ugRecord.save();
      
      res.status(201).json(ugRecord);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });
  

  app.get('/api/ug', async (req, res) => {
    try {
      const records = await UG.find().select('-__v');
      res.json(records);
    } catch (error) {
      res.status(500).json({ error: 'Server error' });
    }
  });
  
  // Create required directories
  ['public', 'documents'].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir);
  });


// Usage Example:
// app.post('/upload', upload.single('up'), (req, res) => { ... });
// app.post('/uploadCertificate', upload.single('certificates'), (req, res) => { ... });


// Routes
app.post('/api/education', upload.single('certificate'), async (req, res) => {
  try {
    const { body, file } = req;
    
    const educationData = {
      ...body,
      percentage: parseFloat(body.percentage),
      fromYear: parseInt(body.fromYear),
      toYear: parseInt(body.toYear),
      certificate: file.path
    };

    const education = new Education(educationData);
    await education.save();
    
    res.status(201).json(education);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.get('/api/education', async (req, res) => {
  try {
    const educations = await Education.find().select('-__v');
    res.json(educations);
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// Create required directories
['public', 'certificates'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir);
});




app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/tenth', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'tenth.html'));
  });

  app.get('/ug', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'ug.html'));
  });

  app.get('/personal', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'personal.html'));
  });
  


  


const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});