const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');
const userController = require('../controllers/users'); // Import controller users

// Đọc public key một lần
const publicKey = fs.readFileSync(path.join(__dirname, '../public.key'));

module.exports = {
  CheckLogin: async function (req, res, next) {
    try {
      if (!req.headers.authorization || !req.headers.authorization.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Bạn chưa đăng nhập' });
      }

      const token = req.headers.authorization.split(' ')[1];

      // Verify với RS256
      const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

      // Lấy user từ DB
      const user = await userController.GetAnUserById(decoded.id);
      if (!user) {
        return res.status(401).json({ message: 'Bạn chưa đăng nhập' });
      }

      req.user = user;
      next();
    } catch (error) {
      console.error('JWT error:', error.message);
      return res.status(401).json({ message: 'Bạn chưa đăng nhập' });
    }
  }
};