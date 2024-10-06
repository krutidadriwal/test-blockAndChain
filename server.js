const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 5000;
const db = new sqlite3.Database(':memory:'); // or provide a filename to create a persistent database

app.use(cors());
app.use(bodyParser.json());

// Create Users Table
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )`);
});

// User Registration
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function(err) {
        if (err) {
            return res.status(400).send('User already exists');
        }
        res.status(201).send('User registered');
    });
});

// User Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;

    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (!user) {
            return res.status(401).send('Invalid credentials');
        }

        const match = await bcrypt.compare(password, user.password);
        if (match) {
            const token = jwt.sign({ username: user.username }, 'your_secret_key', { expiresIn: '1h' });
            res.status(200).json({ token });
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// Get User Profile
app.get('/api/profile', (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) return res.status(403).send('Token required');

    jwt.verify(token, 'your_secret_key', (err, decoded) => {
        if (err) return res.status(403).send('Invalid token');
        res.send(`Welcome ${decoded.username}, this is your profile!`);
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
