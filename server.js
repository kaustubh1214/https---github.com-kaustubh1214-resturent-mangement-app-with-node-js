const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const path = require('path');
const session = require('express-session');

const app = express();

// Middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(session({ secret: 'secret', resave: false, saveUninitialized: true }));

// Serve static files (HTML forms and home page)
app.use(express.static(path.join(__dirname, 'public')));

// MySQL database connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', // Replace with your MySQL password
    database: 'book_db'
});

db.connect(err => {
    if (err) {
        console.error('Error connecting to the database:', err);
        return;
    }
    console.log('Connected to MySQL database.');
});

// Hash password before storing
const hashPassword = async (password) => {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
};

// Redirect to signup page on server start
app.get('/', (req, res) => {
    res.redirect('/signup.html'); // Adjust the path if needed
});

// Signup route
app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    try {
        const hashedPassword = await hashPassword(password);
        const query = 'INSERT INTO users (name, email, password) VALUES (?, ?, ?)';
        db.query(query, [name, email, hashedPassword], (err, result) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(400).send('Email already registered.');
                }
                console.error('Error inserting data:', err);
                return res.status(500).send('Server error');
            }
            res.redirect('/login.html');
        });
    } catch (error) {
        res.status(500).send('Error signing up.');
    }
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = ?';
    db.query(query, [email], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).send('Server error');
        }
        if (results.length === 0) {
            return res.status(400).send('No user found with this email.');
        }

        const user = results[0];
        const validPassword = await bcrypt.compare(password, user.password);

        if (!validPassword) {
            return res.status(400).send('Invalid password.');
        }

        // Save user session
        req.session.userId = user.id;

        // If login is successful, redirect the user to the homepage
        res.redirect('/home.html');
    });
});

// Submit Order Route
app.post('/submit-order', (req, res) => {
    const { table, foodItems, totalPrice } = req.body;
    const userId = req.session.userId;

    if (!userId) {
        return res.status(403).json({ success: false, message: 'User not logged in.' });
    }

    const foodItemsString = foodItems.join(', ');

    const query = 'INSERT INTO orders (user_id, table_name, food_items, total_price) VALUES (?, ?, ?, ?)';
    db.query(query, [userId, table, foodItemsString, totalPrice], (err, result) => {
        if (err) {
            console.error('Error inserting order:', err);
            return res.status(500).json({ success: false, message: 'Error placing order.' });
        }
        res.json({ success: true, message: 'Order placed successfully!' });
    });
});

// Get Orders Route
app.get('/get-orders', (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(403).json({ success: false, message: 'User not logged in.' });
    }

    const query = 'SELECT * FROM orders WHERE user_id = ?';
    db.query(query, [userId], (err, results) => {
        if (err) {
            console.error('Error fetching orders:', err);
            return res.status(500).json({ success: false, message: 'Error fetching orders.' });
        }

        res.json({ success: true, orders: results });
    });
});

// Start server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
