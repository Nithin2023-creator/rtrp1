const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = 9001;

app.use(express.json());
app.use(cors());

// MongoDB connection (Ensure MongoDB is running locally)
mongoose.connect("mongodb://localhost:27017/userdetails", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
});

// Unified Schema
const profileSchema = new mongoose.Schema({
    personalDetails: {
        gender: String,
        dob: String,
        age: Number,
        email: String,
        phone: String,
        tempAddress: {
            area: String,
            city: String,
            state: String,
            pincode: String,
        },
        permAddress: {
            area: String,
            city: String,
            state: String,
            pincode: String,
        },
    },
    education: [
        {
            level: String, // UG, PG, PhD
            university: String,
            duration: { from: String, to: String },
            location: String,
            state: String,
            grade: String,
        },
    ],
    professionalExperience: [
        {
            organization: String,
            joiningDate: String,
            relieveDate: String,
            experienceYears: Number,
            location: String,
        },
    ],
    researchPublications: [
        {
            title: String,
            duration: { from: String, to: String },
        },
    ],
});

const Profile = mongoose.model("Profile", profileSchema);

// Fetch Profile Details
app.get("/profile", async (req, res) => {
    try {
        const profile = await Profile.findOne();
        if (profile) {
            res.json(profile);
        } else {
            res.status(404).json({ message: "No profile found" });
        }
    } catch (error) {
        res.status(500).json({ message: "Server Error", error });
    }
});

// Create or Update Profile
app.post("/profile", async (req, res) => {
    try {
        let profile = await Profile.findOne();
        if (profile) {
            // Update existing profile
            Object.assign(profile, req.body);
        } else {
            // Create new profile
            profile = new Profile(req.body);
        }

        await profile.save();
        res.json({ message: "Profile saved successfully", profile });
    } catch (error) {
        res.status(500).json({ message: "Error saving profile", error });
    }
});

// Update Profile
app.put("/profile", async (req, res) => {
    try {
        let profile = await Profile.findOne();
        if (profile) {
            // Update existing profile
            Object.assign(profile, req.body);
            await profile.save();
            res.json({ message: "Profile updated successfully", profile });
        } else {
            res.status(404).json({ message: "No profile found to update" });
        }
    } catch (error) {
        res.status(500).json({ message: "Error updating profile", error });
    }
});

// Delete Profile
app.delete("/profile", async (req, res) => {
    try {
        const result = await Profile.deleteOne();
        if (result.deletedCount > 0) {
            res.json({ message: "Profile deleted successfully" });
        } else {
            res.status(404).json({ message: "No profile found to delete" });
        }
    } catch (error) {
        res.status(500).json({ message: "Error deleting profile", error });
    }
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, 'my_profile.html')); // Serve the login.html file from the "public" directory
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
