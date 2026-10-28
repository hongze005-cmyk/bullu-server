// 引入需要的包
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config(); // 读取 .env 文件

const dns = require('dns');
dns.setServers(['8.8.8.8','8.8.4.4']);

const app = express();

// 中间件：允许跨域和解析 JSON
app.use(cors());
app.use(express.json());

// ================= 1. 连接数据库 =================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅ 数据库连接成功！'))
  .catch((err) => console.error('❌ 数据库连接失败：', err));

// ================= 2. 设计用户数据模型 =================
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model('User', userSchema);

// ================= 3. 注册接口 =================
app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // 检查用户是否已存在
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: '该用户名已被注册' });

    // 密码加密（核心安全步骤，绝不明文存库）
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 存入数据库
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();

    // 👇【修改点】：注册成功后，直接生成 Token 发给前端
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    // 返回 token 和 user 信息，格式与登录接口保持一致
    res.status(201).json({ 
      message: '注册成功！', 
      token, 
      user: { id: newUser._id, username: newUser.username } 
    });
  } catch (error) {
    res.status(500).json({ message: '服务器错误', error: error.message });
  }
});

// ================= 4. 登录接口 =================
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 找用户
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: '用户名或密码错误' });

    // 比对密码（把用户输入的密码和数据库里加密的密码比对）
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: '用户名或密码错误' });

    // 生成 JWT Token（前端保存这个，以后证明身份）
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({ message: '登录成功！', token, user: { id: user._id, username: user.username } });
  } catch (error) {
    res.status(500).json({ message: '服务器错误', error: error.message });
  }
});

// ================= 启动服务器 =================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 后端服务器已启动: http://localhost:${PORT}`);
});