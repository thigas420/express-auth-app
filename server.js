const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 8082;

app.use(cors());
app.use(bodyParser.json());

const users = [];

const JWT_SECRET = '7Ea60V2i4FIbIDtRarqttUgxggKU9b3M';

const authRouter = express.Router();

authRouter.post('/register', (req, res) => {
    const { name, email, password, role } = req.body;

    if (!name || !email || !password || !role) {
        console.log('Missing fields');
        return res.status(400).json({ message: 'All fields are required' });
    }

    const validRoles = ['fornecedor', 'cliente'];
    if (!validRoles.includes(role)) {
        console.log('Invalid role');
        return res.status(400).json({ message: 'Invalid role' });
    }

    const existingUser = users.find(user => user.email === email);
    if (existingUser) {
        console.log('User already exists');
        return res.status(400).json({ message: 'User already exists' });
    }

    users.push({ name, email, password, role });
    res.status(201).json({ message: 'User registered successfully' });
});

authRouter.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required' });
    }

    const user = users.find(user => user.email === email && user.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }

    const token = jwt.sign({ email: user.email, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

authRouter.post('/validate-token', (req, res) => {
    const { token } = req.body;

    if (!token) {
        return res.status(400).json({ message: 'Token is required' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        res.json({ valid: true, decoded });
    });
});

app.get('/user', (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token is required' });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }

        const user = users.find(user => user.email === decoded.email);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        const { password, ...userWithoutPassword } = user;
        res.json(userWithoutPassword);
    });
});

app.use('/auth', authRouter);

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});