const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
app.use(bodyParser.urlencoded({ extended: false })); 
app.use(bodyParser.json()); 
app.use(express.json());
const port = 3306; // Adjust port number as needed

// Database credentials
const pool = mysql.createPool({
  host: 'b45u0ecukzpafgkphmii-mysql.services.clever-cloud.com',
  user: 'uykr2jlusvmf6geb',
  password: 'IJjVTa0sEYomIpPZ6jTS',
  database: 'b45u0ecukzpafgkphmii'
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).send('Unauthorized access: Token missing');
  jwt.verify(token.replace('Bearer ', ''), 'gaspard', (err, decoded) => {
    if (err) {
      console.error(err);
      return res.status(403).send('Unauthorized access: Invalid or expired token');
    }
    req.userId = decoded.id;
    next();
  });
};

// Get all data from a roles table
app.get('/roles',verifyToken, async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM roles');
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error retrieving roles');
  }
});

// Select Single role
app.get('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM roles WHERE id = ?', [id]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error showing role');
  }
});

// Insert data into users table
app.post('/roles', verifyToken, async (req, res) => {
  const { email, password } = req.body; // Destructure data from request body
  if (!email || !password ) {
    return res.status(400).send('Please provide all required fields (email, password)');
  }
  try {
    // Encrypt the password
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('INSERT INTO roles (email, password) VALUES (?, ?)', [email, hashedPassword]);
    res.json({ message: `Role inserted successfully with ID: ${result.insertId}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error inserting role');
  }
});



// Update role email and password
app.put('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { email, password } = req.body; // Destructure new email and password from request body
  if (!email || !password) {
    return res.status(400).send('Please provide the new email and password');
  }
  try {
    // Encrypt the new password
    const hashedPassword = await bcrypt.hash(password, 10);
    const [result] = await pool.query('UPDATE roles SET email = ?, password = ? WHERE id = ?', [email, hashedPassword, id]);
    res.json({ message: `Role email and password updated successfully for ID: ${id}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating role email and password');
  }
});

// Partially update role email or password
app.patch('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  const { email, password } = req.body; // Destructure new email and password from request body
  try {
    // Check if either email or password is provided
    if (!email && !password) {
      return res.status(400).send('Please provide at least one of the following: email or password');
    }

    // Construct the update query and parameters based on the provided fields
    let updateQuery = 'UPDATE roles SET ';
    let params = [];
    if (email) {
      updateQuery += 'email = ?, ';
      params.push(email);
    }
    if (password) {
      // Encrypt the new password
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += 'password = ?, ';
      params.push(hashedPassword);
    }
    // Remove the trailing comma and add the WHERE clause
    updateQuery = updateQuery.slice(0, -2) + ' WHERE id = ?';
    params.push(id);

    // Perform the update query
    const [result] = await pool.query(updateQuery, params);
    if (result.affectedRows === 0) {
      return res.status(404).send(`Role with ID ${id} not found`);
    }

    res.json({ message: `Role updated successfully for ID: ${id}` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error updating role');
  }
});





// Delete role by ID
app.delete('/roles/:id', verifyToken, async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('DELETE FROM roles WHERE id = ?', [id]);
    res.json({ message: `Data with ID ${id} deleted successfully` });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error deleting role');
  }
});

// Login route
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [users] = await pool.query('SELECT * FROM roles WHERE email = ?', [email]);
    if (!users.length) {
      return res.status(404).send('User not found');
    }

    const user = users[0];
    // Compare the provided password with the hashed password in the database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send('Invalid password');
    }

    // Generate JWT token
    const token = jwt.sign({ id: user.id }, 'gaspard', { expiresIn: '1h' });

    // Send the token as response
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in');
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
