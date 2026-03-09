var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
let jwt = require('jsonwebtoken')
let { checkLogin } = require('../utils/authHandler.js');
const { get } = require('mongoose');
let bcrypt = require('bcrypt');

/* GET home page. */
//localhost:3000
router.post('/register', async function (req, res, next) {
    let newUser = await userController.CreateAnUser(
        req.body.username,
        req.body.password,
        req.body.email,
        "69a5462f086d74c9e772b804"
    )
    res.send({
        message: "dang ki thanh cong"
    })
});
router.post('/login', async function (req, res, next) {
    let result = await userController.QueryByUserNameAndPassword(
        req.body.username, req.body.password
    )
    if (result) {
        let token = jwt.sign({
            id: result.id
        }, 'secret', {
            expiresIn: '1h'
        })
        res.cookie("token", token, {
            maxAge: 60 * 60 * 1000,
            httpOnly: true
        });
        res.send(token)
    } else {
        res.status(404).send({ message: "sai THONG TIN DANG NHAP" })
    }

});
router.get('/me', checkLogin, async function (req, res, next) {
    console.log(req.userId);
    let getUser = await userController.FindUserById(req.userId);
    res.send(getUser);
})

router.post('/logout', checkLogin, function (req, res, next) {
    res.cookie('token', null, {
        maxAge: 0,
        httpOnly: true
    })
    res.send("da logout ")
})

router.post('/change-password', checkLogin, async function (req, res, next) {
    try {
        const { email, oldpassword, newpassword } = req.body;
        
        if (!email || !oldpassword || !newpassword) {
            return res.status(400).send({ message: "Thiếu thông tin email, mật khẩu cũ hoặc mật khẩu mới" });
        }
        
        let getUser = await userController.FindUserById(req.userId);
        if (!getUser) {
            return res.status(404).send({ message: "Không tìm thấy người dùng" });
        }
        
        if (getUser.email !== email) {
            return res.status(400).send({ message: "Email không đúng" });
        }
        
        // So sánh mật khẩu cũ với mật khẩu đã hash trong database
        if (!bcrypt.compareSync(oldpassword, getUser.password)) {
            return res.status(400).send({ message: "Mật khẩu cũ không đúng" });
        }

        // Update password (sẽ được tự động hash bởi pre('save') middleware)
        getUser.password = newpassword;
        await getUser.save();
        
        res.send({ message: "Đổi mật khẩu thành công!" });
    } catch (error) {
        res.status(500).send({ message: "Lỗi server", error: error.message });
    }
})



module.exports = router;
