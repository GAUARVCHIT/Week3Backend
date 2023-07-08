const express = require('express');
const jwt = require('jsonwebtoken');
const Admin = require('../models/admin');
const Course = require('../models/course');
const bcrypt = require('bcrypt');

const router = express.Router();

const authenticateAccessToken = (req, res, next) => {
    // console.log(req.headers);
    const accessToken = req.headers['authorization'];
    if (accessToken) {
        jwt.verify(accessToken, process.env.JWT_SECRET, (err, admin) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.admin = admin;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

router.post('/signup', async (req, res) => {
    try {
        // const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const admin = new Admin({
            username: req.body.username,
            password: req.body.password
        });
        await admin.save();
        res.status(201).json({ message: "Admin created successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
}
);

router.post('/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        const admin = await Admin.findOne({ username });

        if (!admin || !(await bcrypt.compare(password, admin.password))) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        const accessToken = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '15m' });
        const refreshToken = jwt.sign({ id: admin.id, username: admin.username }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });

        admin.refreshToken = refreshToken;
        await admin.save();
        res.json({ accessToken, refreshToken, message: "Logged in successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.post('/refresh', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.sendStatus(401);
    }
    const admin = await Admin.findOne({ refreshToken });
    if (!admin) {
        return res.sendStatus(403);
    }
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, admin) => {
        if (err) {
            return res.sendStatus(403);
        }
        const accessToken = jwt.sign({ id: admin.id, username: admin.username }, process.env.JWT_SECRET, { expiresIn: '15m' });
        res.send({ accessToken });
    });
});

router.post('/courses', authenticateAccessToken, async (req, res) => {
    try {
        const { title, description, price, imageLink, published } = req.body;
        const course = new Course({
            title,
            description,
            price,
            imageLink,
            published
        });
        await course.save();
        res.status(201).json({ message: "Course created successfully", courseId: course.id });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.get('/courses', authenticateAccessToken, async (req, res) => {
    try {
        const courses = await Course.find();
        res.status(200).json(courses);
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});

router.put('/courses/:id', authenticateAccessToken, async (req, res) => {
    try {
        const { title, description, price, imageLink, published } = req.body;
        const course = await Course.findById(req.params.id);
        if (title) {
            course.title = title;
        }
        if (description) {
            course.description = description;
        }
        if (price) {
            course.price = price;
        }
        if (imageLink) {
            course.imageLink = imageLink;
        }
        if (published) {
            course.published = published;
        }
        await course.save();
        res.status(200).json({ message: "Course updated successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


router.delete('/courses/:id', authenticateAccessToken, async (req, res) => {
    try {
        await Course.findByIdAndDelete(req.params.id);
        res.status(200).json({ message: "Course deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: err.message });
    }
});


module.exports = router;
