// backend/routes/auth.js
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Student = require("../models/student");
const auth = require("../middleware/auth");

const router = express.Router();

/* ================= REGISTER ================= */
router.post("/register", async (req, res) => {
  try {
    const { name, email, password, course } = req.body;

    if (!name || !email || !password || !course) {
      return res.status(400).json({ msg: "Please fill all fields" });
    }

    let user = await Student.findOne({ email });

    if (user) {
      return res.status(400).json({ msg: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    user = new Student({
      name,
      email,
      password: hashedPassword,
      course
    });

    await user.save();

    res.status(200).json({ msg: "Registered successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

/* ================= LOGIN ================= */
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await Student.findOne({ email });

    if (!user) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      token,
      user
    });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

/* ================= UPDATE PASSWORD ================= */
router.put("/update-password", auth, async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;

    const user = await Student.findById(req.user.id);

    const isMatch = await bcrypt.compare(oldPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({ msg: "Old password incorrect" });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    res.json({ msg: "Password updated successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

/* ================= UPDATE COURSE ================= */
router.put("/update-course", auth, async (req, res) => {
  try {
    const { course } = req.body;

    const user = await Student.findById(req.user.id);

    user.course = course;
    await user.save();

    res.json({ msg: "Course updated successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

/* ================= DASHBOARD / PROFILE ================= */
router.get("/dashboard", auth, async (req, res) => {
  try {
    const user = await Student.findById(req.user.id).select("-password");
    res.json(user);
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

module.exports = router;