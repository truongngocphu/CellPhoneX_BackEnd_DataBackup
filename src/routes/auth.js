const express = require('express');
const router = express.Router();
const { OAuth2Client } = require('google-auth-library');
const jwt = require('jsonwebtoken');
const AccKH = require('../model/AccKH');

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// POST /api/auth/google
router.post('/google', async (req, res) => {
  const { idToken } = req.body;
  try {
    // 1. Verify idToken với Google
    const ticket = await client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    const payload = ticket.getPayload();
    const { email, name, picture, sub: googleId } = payload;

    // 2. Tìm hoặc tạo user
    let user = await AccKH.findOne({ email });
    if (!user) {
      user = new AccKH({
        email,
        fullName: name,
        image: picture,
        // password để trống
      });
    }

    // 3. Tạo JWT và lưu vào user.tokenAccess
    const token = jwt.sign(
      { _id: user._id, email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    user.tokenAccess = token;
    await user.save();

    // 4. Trả về token và thông tin user
    res.json({
      success: true,
      token,
      user: {
        _id: user._id,
        email: user.email,
        fullName: user.fullName,
        image: user.image,
        hangTV: user.hangTV,
      }
    });
  } catch (err) {
    console.error(err);
    res.status(401).json({ success: false, message: 'Invalid Google token' });
  }
});

module.exports = router;