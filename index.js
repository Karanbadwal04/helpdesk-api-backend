const express = require('express');
const { Pool } = require('pg'); // MODIFIED: Using the PostgreSQL driver instead of sqlite3
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// --- CORS Configuration (Your original, unchanged) ---
const allowedOrigins = [
    'http://localhost:3000',
    'https://helpdesk-react-frontend.onrender.com'
];
app.use(cors({
    origin: function (origin, callback) {
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
            callback(new Error(msg), false);
        }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 200
}));

// --- Middleware (Your original, unchanged) ---
app.use(express.json());

// --- MODIFIED: Database Setup for PostgreSQL ---
const pool = new Pool({
  // This will automatically use the DATABASE_URL environment variable on Render
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- MODIFIED: Create Tables with PostgreSQL Syntax ---
const setupDatabase = async () => {
    const client = await pool.connect();
    try {
        await client.query(`CREATE TABLE IF NOT EXISTS Users (
            id SERIAL PRIMARY KEY,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'agent', 'admin')) DEFAULT 'user'
        )`);
        console.log("Users table is ready.");

        await client.query(`CREATE TABLE IF NOT EXISTS Tickets (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'closed')),
            priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high')),
            created_by_user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
            assigned_to_user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW(),
            due_date TIMESTAMPTZ,
            version INTEGER DEFAULT 1
        )`);
        console.log("Tickets table is ready.");

        await client.query(`CREATE TABLE IF NOT EXISTS Comments (
            id SERIAL PRIMARY KEY,
            content TEXT NOT NULL,
            ticket_id INTEGER REFERENCES Tickets(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )`);
        console.log("Comments table is ready.");

        await client.query(`CREATE TABLE IF NOT EXISTS TicketActions (
            id SERIAL PRIMARY KEY,
            ticket_id INTEGER NOT NULL REFERENCES Tickets(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW()
        )`);
        console.log("TicketActions table is ready.");

    } catch (err) {
        console.error("Error setting up database tables:", err);
    } finally {
        client.release();
    }
};
setupDatabase();


// --- Helper Functions (MODIFIED for PostgreSQL) ---
const addTicketAction = async (ticket_id, user_id, action, details) => {
    const sql = `INSERT INTO TicketActions (ticket_id, user_id, action, details) VALUES ($1, $2, $3, $4)`;
    try {
        await pool.query(sql, [ticket_id, user_id, action, details]);
    } catch (err) {
        console.error("Error logging ticket action:", err.message);
    }
};

const getSLAStatus = (ticket) => {
    if (ticket.status === 'closed') return 'closed';
    if (!ticket.due_date) return 'no_sla';
    const now = new Date();
    const dueDate = new Date(ticket.due_date);
    if (now > dueDate) return 'breached';
    const diffHours = (dueDate - now) / (1000 * 60 * 60);
    if (diffHours <= 12) return 'due_soon';
    return 'on_track';
};

// --- TEMPORARY ADMIN CREATION ENDPOINT ---
app.get('/api/setup-admin-user-temp', async (req, res) => {
    const name = 'admin';
    const username = 'admin123';
    const email = 'admin@mail.com';
    const password = 'admin123';
    const role = 'admin';

    try {
        const existingUser = await pool.query('SELECT * FROM Users WHERE username = $1 OR email = $2', [username, email]);
        if (existingUser.rows.length > 0) {
            return res.status(409).send('Admin user already exists.');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO Users (name, username, email, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        await pool.query(sql, [name, username, email, hashedPassword, role]);
        res.status(201).send('Admin user created successfully! You can now log in.');

    } catch (err) {
        console.error("Error creating admin user:", err);
        res.status(500).send('Server error while creating admin user.');
    }
});
// --- API Endpoints (All converted to PostgreSQL) ---

app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'HelpDesk API is running!' });
});

// User Registration Endpoint
app.post('/api/register', async (req, res) => {
    const { name, username, email, password, role = 'user' } = req.body;
    if (!name || !username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = `INSERT INTO Users (name, username, email, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
        const result = await pool.query(sql, [name, username, email, hashedPassword, role]);
        res.status(201).json({ message: 'User created successfully', userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Username or email already exists' });
        }
        console.error("Registration error:", err);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// User Login Endpoint
app.post('/api/login', async (req, res) => {
    const { loginIdentifier, password } = req.body;
    if (!loginIdentifier || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const sql = `SELECT * FROM Users WHERE email = $1 OR username = $1`;
    try {
        const result = await pool.query(sql, [loginIdentifier]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        res.status(200).json({ message: 'Login successful', userId: user.id, name: user.name, username: user.username, email: user.email, role: user.role });
    } catch (err) {
        console.error("Login database error:", err);
        return res.status(500).json({ error: 'Server error during login' });
    }
});

// Get all users
app.get('/api/users', async (req, res) => {
    const { role } = req.query;
    let sql = `SELECT id, name, email, role FROM Users`;
    const params = [];

    if (role) {
        sql += ` WHERE role = $1`;
        params.push(role);
    }

    try {
        const result = await pool.query(sql, params);
        res.status(200).json({ users: result.rows });
    } catch (err) {
        console.error("Error fetching users:", err.message);
        return res.status(500).json({ error: 'Server error fetching users: ' + err.message });
    }
});

// Get a user's details by ID
app.get('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const sql = `SELECT id, name, username, email, role FROM Users WHERE id = $1`;
    try {
        const result = await pool.query(sql, [id]);
        if (!result.rows[0]) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ user: result.rows[0] });
    } catch (err) {
        console.error("Error fetching user by ID:", err.message);
        return res.status(500).json({ error: 'Server error' });
    }
});

// Update user details
app.patch('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { name, username, email, password } = req.body;

    let fieldsToUpdate = [];
    const params = [];
    let paramCount = 1;

    if (name) {
        fieldsToUpdate.push(`name = $${paramCount++}`);
        params.push(name);
    }
    if (username) {
        fieldsToUpdate.push(`username = $${paramCount++}`);
        params.push(username);
    }
    if (email) {
        fieldsToUpdate.push(`email = $${paramCount++}`);
        params.push(email);
    }
    if (password) {
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            fieldsToUpdate.push(`password = $${paramCount++}`);
            params.push(hashedPassword);
        } catch (error) {
            console.error("Error hashing password for user update:", error);
            return res.status(500).json({ error: 'Error hashing new password' });
        }
    }

    if (fieldsToUpdate.length === 0) {
        return res.status(400).json({ error: 'No fields provided for update.' });
    }

    const sql = `UPDATE Users SET ${fieldsToUpdate.join(', ')} WHERE id = $${paramCount}`;
    params.push(id);

    try {
        const result = await pool.query(sql, params);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'User not found or no changes made.' });
        }
        res.status(200).json({ message: 'User updated successfully' });
    } catch (err) {
        if (err.code === '23505') {
            return res.status(400).json({ error: 'Username or email already taken.' });
        }
        console.error("Failed to update user:", err.message);
        return res.status(500).json({ error: 'Failed to update user: ' + err.message });
    }
});


// Create a new ticket
app.post('/api/tickets', async (req, res) => {
    const { title, description, created_by_user_id, priority = 'medium' } = req.body;
    if (!title || !description || !created_by_user_id) {
        return res.status(400).json({ error: 'Title, description, and userId are required' });
    }

    let due_date = null;
    const now = new Date();
    switch (priority) {
        case 'high': now.setHours(now.getHours() + 4); due_date = now.toISOString(); break;
        case 'medium': now.setHours(now.getHours() + 24); due_date = now.toISOString(); break;
        case 'low': now.setDate(now.getDate() + 3); due_date = now.toISOString(); break;
        default: due_date = null;
    }

    const sql = `INSERT INTO Tickets (title, description, created_by_user_id, priority, due_date) VALUES ($1, $2, $3, $4, $5) RETURNING id`;
    try {
        const result = await pool.query(sql, [title, description, created_by_user_id, priority, due_date]);
        const ticketId = result.rows[0].id;
        await addTicketAction(ticketId, created_by_user_id, 'created', `Ticket created with priority: ${priority}`);
        res.status(201).json({ message: 'Ticket created successfully', ticketId });
    } catch (err) {
        console.error("Failed to create ticket:", err.message);
        return res.status(500).json({ error: 'Failed to create ticket: ' + err.message });
    }
});

// Get all tickets
app.get('/api/tickets', async (req, res) => {
    const { search, status, priority, breached, limit = 10, offset = 0, userId, role } = req.query;

    let baseSql = `
        SELECT
            t.id, t.title, t.description, t.status, t.priority, t.created_at,
            t.updated_at, t.due_date, t.version, u.name as creator_name,
            au.name as assigned_agent_name, t.created_by_user_id, t.assigned_to_user_id
        FROM Tickets t
        LEFT JOIN Users u ON t.created_by_user_id = u.id
        LEFT JOIN Users au ON t.assigned_to_user_id = au.id
    `;
    let countSql = `SELECT COUNT(DISTINCT t.id) as total FROM Tickets t LEFT JOIN Users u ON t.created_by_user_id = u.id`;

    let whereClauses = [];
    const params = [];
    let paramIndex = 1;

    if (role === 'user' && userId) {
        whereClauses.push(`t.created_by_user_id = $${paramIndex++}`);
        params.push(userId);
    } else if (role === 'agent' && userId) {
        whereClauses.push(`(t.assigned_to_user_id = $${paramIndex++} OR t.status = 'open')`);
        params.push(userId);
    }
    if (status && status !== 'all') {
        whereClauses.push(`t.status = $${paramIndex++}`);
        params.push(status);
    }
    if (priority && priority !== 'all') {
        whereClauses.push(`t.priority = $${paramIndex++}`);
        params.push(priority);
    }
    if (breached === 'true') {
        whereClauses.push(`t.status != 'closed' AND t.due_date IS NOT NULL AND t.due_date < NOW()`);
    }
    if (search) {
        const searchTerm = `%${search}%`;
        whereClauses.push(`(t.title ILIKE $${paramIndex++} OR t.description ILIKE $${paramIndex++} OR u.name ILIKE $${paramIndex++})`);
        params.push(searchTerm, searchTerm, searchTerm);
    }

    if (whereClauses.length > 0) {
        const whereString = ' WHERE ' + whereClauses.join(' AND ');
        baseSql += whereString;
        countSql += whereString;
    }

    baseSql += ` ORDER BY t.created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    const finalParams = [...params, Number(limit), Number(offset)];
    
    try {
        const ticketsResult = await pool.query(baseSql, finalParams);
        const countResult = await pool.query(countSql, params);
        
        const ticketsWithSLA = ticketsResult.rows.map(ticket => ({ ...ticket, sla_status: getSLAStatus(ticket) }));
        const totalTickets = countResult.rows[0] ? parseInt(countResult.rows[0].total, 10) : 0;
        
        res.status(200).json({ tickets: ticketsWithSLA, total: totalTickets });
    } catch (err) {
        console.error('Server error fetching tickets:', err.message);
        return res.status(500).json({ error: 'Server error fetching tickets: ' + err.message });
    }
});


// Get a single ticket by ID
// MODIFIED: Corrected the typo from 'aapp' to 'app'
app.get('/api/tickets/:id', async (req, res) => {
    const { id } = req.params;
    const sql = `
        SELECT t.*, creator.name as creator_name, agent.name as assigned_agent_name
        FROM Tickets t
        LEFT JOIN Users creator ON t.created_by_user_id = creator.id
        LEFT JOIN Users agent ON t.assigned_to_user_id = agent.id
        WHERE t.id = $1`;
    try {
        const result = await pool.query(sql, [parseInt(id, 10)]); 

        if (!result.rows[0]) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        let row = result.rows[0];
        row.sla_status = getSLAStatus(row);
        res.status(200).json({ ticket: row });
    } catch (err) {
        console.error("Error fetching single ticket:", err.message);
        return res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

// Update a ticket
app.patch('/api/tickets/:id', async (req, res) => {
    const { id } = req.params;
    const { status, assigned_to_user_id, priority, current_version, user_id: updater_user_id } = req.body;

    if (!updater_user_id) {
        return res.status(400).json({ error: 'User ID of the updater is required.' });
    }

    try {
        const existingTicketResult = await pool.query('SELECT * FROM Tickets WHERE id = $1 FOR UPDATE', [id]);
        const existingTicket = existingTicketResult.rows[0];

        if (!existingTicket) {
            return res.status(404).json({ error: 'Ticket not found.' });
        }
        if (current_version !== existingTicket.version) {
            return res.status(409).json({ error: 'Conflict: Ticket has been updated by someone else. Please refresh and try again.' });
        }

        let fieldsToUpdate = [];
        const params = [];
        const actions = [];
        let paramCount = 1;

        if (status && status !== existingTicket.status) {
            fieldsToUpdate.push(`status = $${paramCount++}`);
            params.push(status);
            actions.push({ action_type: 'status_changed', details: `status: ${existingTicket.status} -> ${status}` });
        }
        if (priority && priority !== existingTicket.priority) {
            fieldsToUpdate.push(`priority = $${paramCount++}`);
            params.push(priority);
            actions.push({ action_type: 'priority_changed', details: `priority: ${existingTicket.priority} -> ${priority}` });
        }
        
        let actualAssignedToUserId = assigned_to_user_id === '' ? null : assigned_to_user_id;
        if (actualAssignedToUserId !== existingTicket.assigned_to_user_id) {
            fieldsToUpdate.push(`assigned_to_user_id = $${paramCount++}`);
            params.push(actualAssignedToUserId);
            actions.push({ action_type: 'assigned', details: `assigned to user ID: ${actualAssignedToUserId || 'unassigned'}` });
        }

        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No meaningful fields to update provided.' });
        }

        fieldsToUpdate.push(`version = $${paramCount++}`);
        params.push(existingTicket.version + 1);
        fieldsToUpdate.push(`updated_at = NOW()`);

        const sql = `UPDATE Tickets SET ${fieldsToUpdate.join(', ')} WHERE id = $${paramCount}`;
        params.push(id);

        const updateResult = await pool.query(sql, params);

        if (updateResult.rowCount === 0) {
            return res.status(404).json({ error: 'Ticket not found or no changes made.' });
        }

        actions.forEach(actionObj => addTicketAction(id, updater_user_id, actionObj.action_type, actionObj.details));
        res.status(200).json({ message: 'Ticket updated successfully', newVersion: existingTicket.version + 1 });

    } catch (error) {
        console.error('Error in PATCH /api/tickets/:id:', error);
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});


// Add a comment to a ticket
app.post('/api/tickets/:id/comments', async (req, res) => {
    const { id: ticket_id } = req.params;
    const { user_id, content } = req.body;
    if (!user_id || !content) {
        return res.status(400).json({ error: 'User ID and content are required' });
    }
    const sql = `INSERT INTO Comments (ticket_id, user_id, content) VALUES ($1, $2, $3) RETURNING id`;
    try {
        const result = await pool.query(sql, [ticket_id, user_id, content]);
        await addTicketAction(ticket_id, user_id, 'commented', content);
        res.status(201).json({ message: 'Comment added successfully', commentId: result.rows[0].id });
    } catch (err) {
        console.error("Failed to add comment:", err.message);
        return res.status(500).json({ error: 'Failed to add comment: ' + err.message });
    }
});

// Get all comments for a specific ticket
app.get('/api/tickets/:id/comments', async (req, res) => {
    const { id: ticket_id } = req.params;
    const sql = `
        SELECT c.id, c.content, c.created_at, u.name as author_name
        FROM Comments c
        JOIN Users u ON c.user_id = u.id
        WHERE c.ticket_id = $1
        ORDER BY c.created_at ASC`;
    try {
        const result = await pool.query(sql, [ticket_id]);
        res.status(200).json({ comments: result.rows });
    } catch (err) {
        console.error("Failed to retrieve comments:", err.message);
        return res.status(500).json({ error: 'Failed to retrieve comments: ' + err.message });
    }
});

// Get all actions for a specific ticket
app.get('/api/tickets/actions/:id', async (req, res) => {
    const { id: ticket_id } = req.params;
    const sql = `
        SELECT ta.id, ta.action, ta.details, ta.created_at, u.name as actor_name
        FROM TicketActions ta
        LEFT JOIN Users u ON ta.user_id = u.id
        WHERE ta.ticket_id = $1
        ORDER BY ta.created_at ASC`;
    try {
        const result = await pool.query(sql, [ticket_id]);
        res.status(200).json({ actions: result.rows });
    } catch (err) {
        console.error("Failed to retrieve ticket actions:", err.message);
        return res.status(500).json({ error: 'Failed to retrieve ticket actions: ' + err.message });
    }
});


// Delete a ticket
app.delete('/api/tickets/:id', async (req, res) => {
    const { id } = req.params;
    try {
        const result = await pool.query(`DELETE FROM Tickets WHERE id = $1`, [id]);
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        res.status(200).json({ message: 'Ticket and all associated data deleted successfully' });
    } catch (err) {
        console.error("Failed to delete ticket:", err.message);
        return res.status(500).json({ error: 'Failed to delete ticket: ' + err.message });
    }
});


// Delete a comment (Admin only)
app.delete('/api/comments/:id', async (req, res) => {
    const { id: commentId } = req.params;
    const { adminId } = req.query;

    if (!adminId) {
        return res.status(400).json({ error: 'Admin ID is required for verification' });
    }
    try {
        const userResult = await pool.query('SELECT role FROM Users WHERE id = $1', [adminId]);
        const user = userResult.rows[0];

        if (!user) {
            return res.status(400).json({ error: 'Invalid Admin ID or user not found.' });
        }
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Only admins can delete comments' });
        }

        const deleteResult = await pool.query(`DELETE FROM Comments WHERE id = $1`, [commentId]);

        if (deleteResult.rowCount === 0) {
            return res.status(404).json({ error: 'Comment not found' });
        }
        res.status(200).json({ message: 'Comment deleted successfully' });
    } catch (err) {
        console.error("Failed to delete comment:", err.message);
        return res.status(500).json({ error: 'Failed to delete comment: ' + err.message });
    }
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});

module.exports = app;

