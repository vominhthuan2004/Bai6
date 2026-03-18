let userModel = require("../schemas/users");
const bcrypt = require('bcrypt'); // Thêm bcrypt để hash và so sánh mật khẩu

module.exports = {
    CreateAnUser: async function (username, password, email, role,
        fullName, avatarUrl, status, loginCount
    ) {
        let newItem = new userModel({
            username: username,
            password: password,
            email: email,
            fullName: fullName,
            avatarUrl: avatarUrl,
            status: status,
            role: role,
            loginCount: loginCount
        });
        await newItem.save();
        return newItem;
    },
    GetAllUser: async function () {
        let users = await userModel.find({ isDeleted: false });
        return users;
    },
    GetAnUserByUsername: async function (username) {
        let user = await userModel.findOne({ isDeleted: false, username: username });
        return user;
    },
    GetAnUserById: async function (id) {
        let user = await userModel.findOne({ isDeleted: false, _id: id });
        return user;
    },
    // Thêm hàm tìm user theo email (dùng cho login)
    GetAnUserByEmail: async function (email) {
        return await userModel.findOne({ isDeleted: false, email: email });
    },
    // Hàm đổi mật khẩu (yêu cầu đăng nhập)
    changePassword: async function (req, res) {
        try {
            const { oldpassword, newpassword } = req.body;

            if (!oldpassword || !newpassword) {
                return res.status(400).json({ message: 'Vui lòng nhập mật khẩu cũ và mới' });
            }

            // Validate mật khẩu mới: ít nhất 8 ký tự, 1 chữ hoa, 1 số, 1 ký tự đặc biệt
            const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
            if (!passwordRegex.test(newpassword)) {
                return res.status(400).json({
                    message: 'Mật khẩu mới phải có ít nhất 8 ký tự, bao gồm chữ hoa, số và ký tự đặc biệt'
                });
            }

            const user = req.user; // từ middleware CheckLogin

            // Kiểm tra mật khẩu cũ
            const isMatch = await bcrypt.compare(oldpassword, user.password);
            if (!isMatch) {
                return res.status(401).json({ message: 'Mật khẩu cũ không đúng' });
            }

            // Hash mật khẩu mới
            const hashed = await bcrypt.hash(newpassword, 10);
            await userModel.findByIdAndUpdate(user._id, { password: hashed });

            res.json({ message: 'Đổi mật khẩu thành công' });
        } catch (error) {
            console.error(error);
            res.status(500).json({ message: 'Lỗi server' });
        }
    }
};