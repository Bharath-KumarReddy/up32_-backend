const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const app = express();

app.use(bodyParser.json());
app.use(cors());

const secretKey = 'bharathkumar';
const usersFile = 'users.json';
const dataFile = 'data.json';

const readJSONFile = (filename) => {
    if (fs.existsSync(filename)) {
      const fileContent = fs.readFileSync(filename, 'utf-8');
      try {
        return JSON.parse(fileContent);
      } catch (e) {
        return []; 
      }
    }
    return []; 
  };
  

const writeJSONFile = (filename, content) => {
  fs.writeFileSync(filename, JSON.stringify(content, null, 2), 'utf-8');
};

app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const users = readJSONFile(usersFile);
  const hashedPassword = bcrypt.hashSync(password, 8);

  users.push({ username, password: hashedPassword });
  writeJSONFile(usersFile, users);

  res.status(201).send({ message: 'User registered successfully' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const users = readJSONFile(usersFile);
  const user = users.find((u) => u.username === username);

  if (user && bcrypt.compareSync(password, user.password)) {
    const token = jwt.sign({ username }, secretKey, { expiresIn: '1h' });
    res.send({ token });
  } else {
    res.status(401).send({ message: 'Invalid credentials' });
  }
});

const verifyToken = (req, res, next) => {
  const token = req.headers['x-access-token'];
  if (!token) return res.status(403).send({ message: 'No token provided' });

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) return res.status(500).send({ message: 'Failed to authenticate token' });

    req.username = decoded.username;
    next();
  });
};

app.post('/save', verifyToken, (req, res) => {
  const data = req.body;
  writeJSONFile(dataFile, data);
  res.send({ message: 'Data saved successfully' });
});

app.get('/read', verifyToken, (req, res) => {
  const data = readJSONFile(dataFile);
  res.send(data);
});

app.listen(5000, () => {
  console.log('Server is running on port 5000');
});
