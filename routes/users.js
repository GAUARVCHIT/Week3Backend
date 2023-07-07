require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const User = require('../models/user');
const bcrypt = require('bcrypt');

// create a router so users can sign up, signup should contain username and password and output 
// should be  message: "User created successfully"
const router = express.Router();
router.post('/signup', async (req, res) => {
    try {
        // const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: req.body.password
        });
        await user.save();
        res.status(201).json({ message: "User created successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
}
);

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const user = await User.findOne({ username });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        const accessToken = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ id: user.id, username: user.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        user.refreshToken = refreshToken;
        await user.save();
        res.json({ accessToken, refreshToken, message: "Logged in successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/refresh', async (req, res) => {
    const {refreshToken} = req.body;
    if(!refreshToken) {
      return res.sendStatus(401);
    }
    const user = await User.findOne({refreshToken});
    if(!user) {
      return res.sendStatus(403);
    }
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if(err) {
        return res.sendStatus(403);
      }
      const accessToken = jwt.sign({id: user.id, username: user.username}, process.env.JWT_SECRET, {expiresIn: '1m'});
      res.send({accessToken});
    });
  });  

module.exports = router;