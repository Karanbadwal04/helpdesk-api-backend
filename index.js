const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3001;

// --- CORS Configuration ---
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

app.use(express.json());

// --- Database Setup for PostgreSQL ---
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

// --- Create Tables with PostgreSQL Syntax ---
const createTables = async () => {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS Users (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('user', 'agent', 'admin')) DEFAULT 'user'
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS Tickets (
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
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS Comments (
                id SERIAL PRIMARY KEY,
                content TEXT NOT NULL,
                ticket_id INTEGER REFERENCES Tickets(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS TicketActions (
                id SERIAL PRIMARY KEY,
                ticket_id INTEGER NOT NULL REFERENCES Tickets(id) ON DELETE CASCADE,
                user_id INTEGER REFERENCES Users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                details TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
        `);
        console.log("Tables checked/created successfully.");
    } catch (err) {
        console.error("Error creating tables:", err);
    } finally {
        client.release();
    }
};

createTables();

// --- Helper Functions ---
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


// --- API Endpoints ---

app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/register', async (req, res) => {
    const { name, username, email, password, role = 'user' } = req.body;
    if (!name || !username || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO Users (name, username, email, password, role) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [name, username, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'User created', userId: result.rows[0].id });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Username or email already exists' });
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    const { loginIdentifier, password } = req.body;
    if (!loginIdentifier || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    try {
        const result = await pool.query(`SELECT * FROM Users WHERE email = $1 OR username = $1`, [loginIdentifier]);
        const user = result.rows[0];
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        res.status(200).json({ userId: user.id, name: user.name, username: user.username, email: user.email, role: user.role });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

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
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/users/:id', async (req, res) => {
    try {
        const result = await pool.query(`SELECT id, name, username, email, role FROM Users WHERE id = $1`, [req.params.id]);
        if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        res.status(200).json({ user: result.rows[0] });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.patch('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { name, username, email, password } = req.body;
    let fieldsToUpdate = [];
    const params = [];
    let paramIndex = 1;

    if (name) { fieldsToUpdate.push(`name = $${paramIndex++}`); params.push(name); }
    if (username) { fieldsToUpdate.push(`username = $${paramIndex++}`); params.push(username); }
    if (email) { fieldsToUpdate.push(`email = $${paramIndex++}`); params.push(email); }
    if (password) {
        const hashedPassword = await bcrypt.hash(password, 10);
        fieldsToUpdate.push(`password = $${paramIndex++}`);
        params.push(hashedPassword);
    }

    if (fieldsToUpdate.length === 0) return res.status(400).json({ error: 'No fields to update' });
    
    params.push(id);
    const sql = `UPDATE Users SET ${fieldsToUpdate.join(', ')} WHERE id = $${paramIndex}`;
    
    try {
        const result = await pool.query(sql, params);
        if (result.rowCount === 0) return res.status(404).json({ error: 'User not found' });
        res.status(200).json({ message: 'User updated successfully' });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'Username or email already taken' });
        res.status(500).json({ error: 'Failed to update user' });
    }
});

app.post('/api/tickets', async (req, res) => {
    const { title, description, created_by_user_id, priority = 'medium' } = req.body;
    if (!title || !description || !created_by_user_id) {
        return res.status(400).json({ error: 'Required fields are missing' });
    }

    let due_date = null;
    const now = new Date();
    switch (priority) {
        case 'high': now.setHours(now.getHours() + 4); due_date = now; break;
        case 'medium': now.setHours(now.getHours() + 24); due_date = now; break;
        case 'low': now.setDate(now.getDate() + 3); due_date = now; break;
    }
    
    try {
        const result = await pool.query(
            `INSERT INTO Tickets (title, description, created_by_user_id, priority, due_date) VALUES ($1, $2, $3, $4, $5) RETURNING id`,
            [title, description, created_by_user_id, priority, due_date]
        );
        const ticketId = result.rows[0].id;
        await addTicketAction(ticketId, created_by_user_id, 'created', `Priority: ${priority}`);
        res.status(201).json({ ticketId });
    } catch (err) {
        res.status(500).json({ error: 'Failed to create ticket' });
    }
});

app.get('/api/tickets', async (req, res) => {
    const { search, status, priority, breached, limit = 10, offset = 0, userId, role } = req.query;

    let whereClauses = [];
    const params = [];
    let paramIndex = 1;

    if (role === 'user' && userId) { whereClauses.push(`t.created_by_user_id = $${paramIndex++}`); params.push(userId); }
    if (role === 'agent' && userId) { whereClauses.push(`(t.assigned_to_user_id = $${paramIndex++} OR t.status = 'open')`); params.push(userId); }
    if (status && status !== 'all') { whereClauses.push(`t.status = $${paramIndex++}`); params.push(status); }
    if (priority && priority !== 'all') { whereClauses.push(`t.priority = $${paramIndex++}`); params.push(priority); }
    if (breached === 'true') { whereClauses.push(`t.status != 'closed' AND t.due_date IS NOT NULL AND t.due_date < NOW()`); }
    if (search) {
        const searchTerm = `%${search}%`;
        whereClauses.push(`(t.title ILIKE $${paramIndex++} OR t.description ILIKE $${paramIndex++})`);
        params.push(searchTerm, searchTerm);
    }

    const whereString = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
    const baseSql = `
        SELECT t.id, t.title, t.status, t.priority, t.created_at, t.due_date, t.version, u.name as creator_name, au.name as assigned_agent_name
        FROM Tickets t
        LEFT JOIN Users u ON t.created_by_user_id = u.id
        LEFT JOIN Users au ON t.assigned_to_user_id = au.id
        ${whereString}
        ORDER BY t.created_at DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`;
    const countSql = `SELECT COUNT(t.id) as total FROM Tickets t ${whereString}`;

    try {
        const ticketResult = await pool.query(baseSql, [...params, limit, offset]);
        const countResult = await pool.query(countSql, params);
        
        const ticketsWithSLA = ticketResult.rows.map(ticket => ({...ticket, sla_status: getSLAStatus(ticket)}));
        res.status(200).json({ tickets: ticketsWithSLA, total: parseInt(countResult.rows[0].total, 10) });
    } catch (err) {
        res.status(500).json({ error: 'Server error fetching tickets' });
    }
});

app.get('/api/tickets/:id', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.*, c.name as creator_name, a.name as assigned_agent_name
             FROM Tickets t
             LEFT JOIN Users c ON t.created_by_user_id = c.id
             LEFT JOIN Users a ON t.assigned_to_user_id = a.id
             WHERE t.id = $1`, [req.params.id]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Ticket not found' });
        const ticket = {...result.rows[0], sla_status: getSLAStatus(result.rows[0])};
        res.status(200).json({ ticket });
    } catch (err) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.patch('/api/tickets/:id', async (req, res) => {
    const { id } = req.params;
    const { status, assigned_to_user_id, priority, current_version, user_id: updater_user_id } = req.body;
    
    try {
        const ticketResult = await pool.query('SELECT * FROM Tickets WHERE id = $1', [id]);
        if (ticketResult.rows.length === 0) return res.status(404).json({ error: 'Ticket not found' });
        
        const existingTicket = ticketResult.rows[0];
        if (current_version !== existingTicket.version) {
            return res.status(409).json({ error: 'Conflict: Ticket updated by someone else. Please refresh.' });
        }
        
        // Build update query
        let fields = [], params = [], i = 1;
        if (status) { fields.push(`status = $${i++}`); params.push(status); }
        if (priority) { fields.push(`priority = $${i++}`); params.push(priority); }
        if (assigned_to_user_id !== undefined) { fields.push(`assigned_to_user_id = $${i++}`); params.push(assigned_to_user_id === '' ? null : assigned_to_user_id); }
        
        if (fields.length === 0) return res.status(400).json({ error: 'No fields to update' });
        
        fields.push(`version = $${i++}`, `updated_at = NOW()`);
        params.push(existingTicket.version + 1, id);

        const updateResult = await pool.query(`UPDATE Tickets SET ${fields.join(', ')} WHERE id = $${i++}`, params);

        if (updateResult.rowCount > 0) {
            // Log actions (simplified for brevity)
            if (status && status !== existingTicket.status) await addTicketAction(id, updater_user_id, 'status_changed', status);
            res.status(200).json({ message: 'Ticket updated', newVersion: existingTicket.version + 1 });
        } else {
            res.status(404).json({ error: 'Ticket not found or no changes made.' });
        }
    } catch (err) {
        res.status(500).json({ error: 'Server error updating ticket' });
    }
});

app.delete('/api/tickets/:id', async (req, res) => {
    try {
        // ON DELETE CASCADE on Comments and TicketActions tables handles cleanup
        const result = await pool.query('DELETE FROM Tickets WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Ticket not found' });
        res.status(200).json({ message: 'Ticket deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error deleting ticket' });
    }
});

app.post('/api/tickets/:id/comments', async (req, res) => {
    const { id: ticket_id } = req.params;
    const { user_id, content } = req.body;
    if (!user_id || !content) return res.status(400).json({ error: 'Required fields missing' });
    try {
        const result = await pool.query(
            `INSERT INTO Comments (ticket_id, user_id, content) VALUES ($1, $2, $3) RETURNING id`,
            [ticket_id, user_id, content]
        );
        await addTicketAction(ticket_id, user_id, 'commented', content.substring(0, 50) + '...');
        res.status(201).json({ message: 'Comment added', commentId: result.rows[0].id });
    } catch (err) {
        res.status(500).json({ error: 'Failed to add comment' });
    }
});

app.get('/api/tickets/:id/comments', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT c.*, u.name as author_name FROM Comments c JOIN Users u ON c.user_id = u.id WHERE c.ticket_id = $1 ORDER BY c.created_at ASC`,
            [req.params.id]
        );
        res.status(200).json({ comments: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve comments' });
    }
});

app.get('/api/tickets/actions/:id', async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT ta.*, u.name as actor_name FROM TicketActions ta LEFT JOIN Users u ON ta.user_id = u.id WHERE ta.ticket_id = $1 ORDER BY ta.created_at ASC`,
            [req.params.id]
        );
        res.status(200).json({ actions: result.rows });
    } catch (err) {
        res.status(500).json({ error: 'Failed to retrieve actions' });
    }
});

app.delete('/api/comments/:id', async (req, res) => {
    const { id: commentId } = req.params;
    const { adminId } = req.query;
    if (!adminId) return res.status(400).json({ error: 'Admin ID is required' });
    try {
        const userResult = await pool.query('SELECT role FROM Users WHERE id = $1', [adminId]);
        if (userResult.rows.length === 0 || userResult.rows[0].role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Admin access required' });
        }
        const deleteResult = await pool.query('DELETE FROM Comments WHERE id = $1', [commentId]);
        if (deleteResult.rowCount === 0) return res.status(404).json({ error: 'Comment not found' });
        res.status(200).json({ message: 'Comment deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Server error deleting comment' });
    }
});


app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server is running on port ${PORT}`);
});