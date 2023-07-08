require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const usersRoutes = require('./routes/users');
const adminRoutes = require('./routes/admin');

const app = express();

app.use(cors());

mongoose.connect(process.env.DATABASE_URL, { useNewUrlParser: true, useUnifiedTopology: true });
app.use(express.json());
app.use('/users', usersRoutes)
app.use('/admin', adminRoutes);
app.listen(3000, () => console.log('Server started on port 3000'));