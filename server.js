const express = require('express');
const path = require('path');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key-that-should-be-in-env-vars';
const AUTH_COOKIE_NAME = 'kasistays_jwt';

// --- DATABASE CONNECTION ---
// IMPORTANT: Use environment variables in a real application for security.
// Ensure you have a .env file or have set these variables in your environment.
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '', // SET YOUR DB PASSWORD HERE OR IN .env
    database: process.env.DB_NAME || 'kasistays'
};

const pool = mysql.createPool(dbConfig);

// Test database connection on startup
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Successfully connected to the MySQL database.');
        connection.release();
    } catch (error) {
        console.error('❌ DATABASE CONNECTION FAILED ❌');
        console.error(`Error: ${error.message}`);
        console.error('Please check your database credentials in server.js and ensure the MySQL server is running.');
        process.exit(1); // Exit if DB connection fails
    }
})();


// --- MIDDLEWARE ---
app.use(express.json()); // To parse JSON bodies
app.use(cookieParser()); // To parse cookies
app.use(express.static(path.join(__dirname, 'public'))); // Serve static frontend files

// Middleware to verify JWT and set user data on req object
const authenticateUser = (req, res, next) => {
    const token = req.cookies[AUTH_COOKIE_NAME];
    if (!token) {
        return next();
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        // The decoded payload is attached to the request
        req.user = { id: decoded.id, email: decoded.email, role: decoded.role, is_verified: decoded.isVerified };
    } catch (error) {
        // If token is invalid (e.g., expired), clear the cookie
        console.error('JWT Verification Error:', error.message);
        res.clearCookie(AUTH_COOKIE_NAME, { path: '/' });
    }
    
    next();
};

app.use(authenticateUser);

// --- API ROUTES ---

// [AUTH]
app.post('/api/auth/signup', async (req, res) => {
    const { email, password, role } = req.body;
    if (!email || !password || !role) {
        return res.status(400).json({ message: 'Email, password, and role are required.' });
    }
    try {
        const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
        const [result] = await pool.query(
            'INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)',
            [email, passwordHash, role]
        );
        const newUser = { id: result.insertId, email, role, isVerified: false };
        
        // Generate JWT
        const token = jwt.sign(newUser, JWT_SECRET, { expiresIn: '1d' });

        res.cookie(AUTH_COOKIE_NAME, token, { 
            httpOnly: true, 
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000, // 1 day
            path: '/' 
        });

        res.status(201).json(newUser);
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Email already in use.' });
        }
        console.error(error);
        res.status(500).json({ message: 'Database error during sign up.' });
    }
});

app.post('/api/auth/signin', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ message: 'Email and password are required.' });
    }
    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }
        const match = await bcrypt.compare(password, user.password_hash);
        if (match) {
            const userProfile = { uid: user.id, email: user.email, role: user.role, isVerified: !!user.is_verified };
            
            // Generate JWT
            const tokenPayload = { id: user.id, email: user.email, role: user.role, isVerified: !!user.is_verified };
            const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1d' });

            res.cookie(AUTH_COOKIE_NAME, token, { 
                httpOnly: true, 
                secure: process.env.NODE_ENV === 'production',
                maxAge: 24 * 60 * 60 * 1000, // 1 day
                path: '/' 
            });

            res.json(userProfile);
        } else {
            res.status(401).json({ message: 'Invalid credentials.' });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Server error during sign in.' });
    }
});

app.post('/api/auth/signout', (req, res) => {
    res.clearCookie(AUTH_COOKIE_NAME, { path: '/' });
    res.status(200).json({ message: 'Signed out successfully.' });
});

app.get('/api/auth/me', (req, res) => {
    if (req.user) {
        // Renaming id to uid to match frontend type
        const { id, is_verified, ...rest } = req.user;
        res.json({ uid: id, isVerified: !!is_verified, ...rest });
    } else {
        res.status(401).json(null);
    }
});


// [DATA]
const mapListingData = (rows) => {
    return rows.map(row => ({
        id: row.id.toString(),
        landlordId: row.landlord_id.toString(),
        title: row.title,
        price: parseFloat(row.price),
        imageUrl: row.imageUrl,
        location: row.location,
        isVerified: !!row.is_landlord_verified,
        gpsCoordinates: {
            lat: parseFloat(row.gps_lat),
            lng: parseFloat(row.gps_lng),
        }
    }));
};

app.get('/api/listings', async (req, res) => {
    const { q } = req.query;
    try {
        let query = `
            SELECT
                l.id, l.landlord_id, l.title, l.price_per_month AS price, l.image_url AS imageUrl, l.location_address AS location, l.gps_lat, l.gps_lng, u.is_verified AS is_landlord_verified
            FROM listings l
            JOIN users u ON l.landlord_id = u.id
            WHERE l.is_active = TRUE
        `;
        const params = [];

        if (q) {
            query += ' AND (l.title LIKE ? OR l.location_address LIKE ?)';
            params.push(`%${q}%`, `%${q}%`);
        }

        const [rows] = await pool.query(query, params);
        res.json(mapListingData(rows));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch listings.' });
    }
});

app.get('/api/listings/recent', async (req, res) => {
    try {
        const [rows] = await pool.query(`
            SELECT
                l.id, l.landlord_id, l.title, l.price_per_month AS price, l.image_url AS imageUrl, l.location_address AS location, l.gps_lat, l.gps_lng, l.created_at, u.is_verified AS is_landlord_verified
            FROM listings l
            JOIN users u ON l.landlord_id = u.id
            WHERE l.is_active = TRUE
            ORDER BY l.created_at DESC
            LIMIT 8;
        `);
        res.json(mapListingData(rows));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch recent listings.' });
    }
});


app.get('/api/providers', async (req, res) => {
    const { q } = req.query;
    try {
        let query = `
            SELECT
                u.id,
                spp.full_name AS name,
                spp.service_category AS service,
                spp.contact_phone AS contact,
                u.profile_image_url AS imageUrl
            FROM users u
            JOIN service_provider_profiles spp ON u.id = spp.user_id
            WHERE u.role = 'provider'
        `;
        const params = [];

        if (q) {
            query += ' AND (spp.full_name LIKE ? OR spp.service_category LIKE ?)';
            params.push(`%${q}%`, `%${q}%`);
        }

        const [rows] = await pool.query(query, params);
        res.json(rows.map(r => ({...r, id: r.id.toString()})));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch service providers.' });
    }
});

// [MAINTENANCE]
app.get('/api/maintenance-requests', authenticateUser, async (req, res) => {
    if (!req.user) {
        return res.status(401).json({ message: 'Authentication required.' });
    }
    try {
        let query = 'SELECT id, listing_id AS listingId, issue_description AS issue, status, created_at AS createdAt FROM maintenance_requests WHERE';
        if (req.user.role === 'student') {
            query += ' student_id = ?';
        } else if (req.user.role === 'landlord') {
            query += ' landlord_id = ?';
        } else {
            return res.json([]);
        }
        query += ' ORDER BY createdAt DESC';
        
        const [rows] = await pool.query(query, [req.user.id]);
        res.json(rows.map(r => ({...r, id: r.id.toString(), listingId: r.listingId.toString()})));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch maintenance requests.' });
    }
});

app.put('/api/maintenance-requests/:id', authenticateUser, async (req, res) => {
    if (!req.user || req.user.role !== 'landlord') {
        return res.status(403).json({ message: 'Permission denied.' });
    }
    const { status } = req.body;
    const { id } = req.params;
    try {
        await pool.query(
            'UPDATE maintenance_requests SET status = ? WHERE id = ? AND landlord_id = ?',
            [status, id, req.user.id]
        );
        res.json({ message: 'Status updated.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to update request.' });
    }
});

// [MESSAGING]
// Start or get a conversation
app.post('/api/conversations', authenticateUser, async (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Authentication required' });
    
    const { recipientId, listingId } = req.body;
    const senderId = req.user.id;

    if (!recipientId) return res.status(400).json({ message: 'Recipient ID is required' });

    try {
        // Check if a conversation between these users for this listing already exists
        const [existing] = await pool.query(`
            SELECT c.id FROM conversations c
            JOIN conversation_participants cp1 ON c.id = cp1.conversation_id AND cp1.user_id = ?
            JOIN conversation_participants cp2 ON c.id = cp2.conversation_id AND cp2.user_id = ?
            WHERE c.listing_id <=> ?
        `, [senderId, recipientId, listingId]);

        if (existing.length > 0) {
            return res.json({ id: existing[0].id.toString() });
        }

        // Create new conversation
        const connection = await pool.getConnection();
        await connection.beginTransaction();
        
        const [convoResult] = await connection.query('INSERT INTO conversations (listing_id) VALUES (?)', [listingId]);
        const conversationId = convoResult.insertId;

        await connection.query('INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?), (?, ?)', [conversationId, senderId, conversationId, recipientId]);
        
        await connection.commit();
        connection.release();

        res.status(201).json({ id: conversationId.toString() });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to start conversation' });
    }
});

// Get all conversations for a user
app.get('/api/conversations', authenticateUser, async (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Authentication required' });

    try {
        const [conversations] = await pool.query(`
            SELECT
                c.id,
                l.title AS listingTitle,
                other_user.id AS participantId,
                other_user.email AS participantEmail,
                other_user.profile_image_url as participantImageUrl,
                last_message.content AS lastMessage,
                last_message.created_at AS lastMessageTimestamp
            FROM conversations c
            JOIN conversation_participants cp_self ON c.id = cp_self.conversation_id AND cp_self.user_id = ?
            JOIN conversation_participants cp_other ON c.id = cp_other.conversation_id AND cp_other.user_id != ?
            JOIN users other_user ON cp_other.user_id = other_user.id
            LEFT JOIN listings l ON c.listing_id = l.id
            LEFT JOIN (
                SELECT m.* FROM messages m
                INNER JOIN (
                    SELECT conversation_id, MAX(created_at) as max_created_at
                    FROM messages
                    GROUP BY conversation_id
                ) AS latest_message ON m.conversation_id = latest_message.conversation_id AND m.created_at = latest_message.max_created_at
            ) AS last_message ON c.id = last_message.conversation_id
            ORDER BY last_message.created_at DESC;
        `, [req.user.id, req.user.id]);
        
        res.json(conversations.map(c => ({...c, id: c.id.toString(), participantId: c.participantId.toString() })));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch conversations' });
    }
});

// Get messages for a conversation
app.get('/api/conversations/:id/messages', authenticateUser, async (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Authentication required' });
    
    const { id } = req.params;
    try {
        // Check if user is part of the conversation
        const [participants] = await pool.query('SELECT user_id FROM conversation_participants WHERE conversation_id = ?', [id]);
        if (!participants.some(p => p.user_id === req.user.id)) {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const [messages] = await pool.query(`
            SELECT id, sender_id AS senderId, content, created_at AS timestamp
            FROM messages
            WHERE conversation_id = ?
            ORDER BY created_at ASC
        `, [id]);
        
        res.json(messages.map(m => ({...m, id: m.id.toString(), senderId: m.senderId.toString() })));
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to fetch messages' });
    }
});

// Send a message
app.post('/api/conversations/:id/messages', authenticateUser, async (req, res) => {
    if (!req.user) return res.status(401).json({ message: 'Authentication required' });
    
    const { id } = req.params;
    const { content } = req.body;
    try {
        const [participants] = await pool.query('SELECT user_id FROM conversation_participants WHERE conversation_id = ?', [id]);
        if (!participants.some(p => p.user_id === req.user.id)) {
            return res.status(403).json({ message: 'Access denied' });
        }
        
        const [result] = await pool.query(
            'INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)',
            [id, req.user.id, content]
        );
        
        const [newMessage] = await pool.query('SELECT id, sender_id as senderId, content, created_at as timestamp FROM messages WHERE id = ?', [result.insertId]);

        res.status(201).json(newMessage[0]);
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Failed to send message' });
    }
});


// --- SPA Fallback ---
// This should be the last route. It sends the React app for any unhandled routes.
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});