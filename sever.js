const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
var cors = require('cors')

app.use(cors())
app.use(express.json());

const PORT = 3000;

const users = [
  {
    "id": 1,
    "username": "testuser",
    "password": "123"
  }
];
let userId = 1;
const refreshTokens = [];

const ACCESS_TOKEN_SECRET = 'youraccesstokensecret';
const REFRESH_TOKEN_SECRET = 'yourrefreshtokensecret';

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) return res.sendStatus(403);

  const accessToken = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '20m' });
  const refreshToken = jwt.sign({ id: user.id, username: user.username }, REFRESH_TOKEN_SECRET);

  refreshTokens.push(refreshToken);
  res.json({ accessToken, refreshToken });
});

app.post('/token', (req, res) => {
  const { token } = req.body;
  if (!token) return res.sendStatus(401);
  if (!refreshTokens.includes(token)) return res.sendStatus(403);

  jwt.verify(token, REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);

    const accessToken = jwt.sign({ id: user.id, username: user.username }, ACCESS_TOKEN_SECRET, { expiresIn: '20m' });
    res.json({ accessToken });
  });
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) {
    console.log('No token found');
    return res.sendStatus(401);
  }

  jwt.verify(token, ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      console.log('Token verification failed:', err);
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
}

app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'Đây là thông tin bảo vệ', user: req.user });
});

app.post('/users', authenticateToken, (req, res) => {
  const { username, password } = req.body;
  const user = { id: userId++, username, password };
  users.push(user);
  res.status(201).json(user);
});

app.get('/users', authenticateToken, (req, res) => {
  res.json(users);
});

app.get('/users/:id', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.sendStatus(404);
  res.json(user);
});

app.put('/users/:id', authenticateToken, (req, res) => {
  const user = users.find(u => u.id === parseInt(req.params.id));
  if (!user) return res.sendStatus(404);

  const { username, password } = req.body;
  user.username = username;
  user.password = password;
  res.json(user);
});

app.delete('/users/:id', authenticateToken, (req, res) => {
  const userIndex = users.findIndex(u => u.id === parseInt(req.params.id));
  if (userIndex === -1) return res.sendStatus(404);

  users.splice(userIndex, 1);
  res.sendStatus(204);
});

app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
