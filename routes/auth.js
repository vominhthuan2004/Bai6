const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const userController = require('../controllers/users'); // Import

// Đọc private key
const privateKey = fs.readFileSync(path.join(__dirname, '../private.key'));

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Giả sử bạn có hàm GetUserByEmail trong controller
    const user = await userController.GetAnUserByEmail(email);
    if (!user) {
      return res.status(401).json({ message: 'Email hoặc mật khẩu không đúng' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Email hoặc mật khẩu không đúng' });
    }

    const payload = { id: user._id, email: user.email, role: user.role };
    const token = jwt.sign(payload, privateKey, { algorithm: 'RS256', expiresIn: '7d' });

    res.json({
      message: 'Đăng nhập thành công',
      token,
      user: { id: user._id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Lỗi server' });
  }
});

module.exports = router;