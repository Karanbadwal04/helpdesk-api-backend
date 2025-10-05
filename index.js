const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cors = require('cors'); // Ensure cors is installed: npm install cors

const app = express();

// --- MODIFICATION 1: Use Render's PORT environment variable or fallback for local dev ---
const PORT = process.env.PORT || 3001;

// --- MODIFICATION 2: Explicit CORS Configuration for better security and clarity ---
// Your deployed frontend URL is: https://helpdesk-react-frontend.onrender.com
const allowedOrigins = [
    'http://localhost:3000', // Your frontend's local development URL
    'https://helpdesk-react-frontend.onrender.com' // Your deployed Render frontend URL
    // Add any other specific domains if your frontend might be accessed from them (e.g., custom domains)
];

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps, Postman, or curl requests)
        // or requests from the allowed origins list.
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            const msg = `The CORS policy for this site does not allow access from the specified Origin: ${origin}`;
            callback(new Error(msg), false);
        }
    },
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE', // Define the HTTP methods your API supports
    credentials: true, // Set to true if your frontend needs to send cookies or authorization headers
    optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
}));


// --- Middleware ---
app.use(express.json());

// --- Database Setup ---
const db = new sqlite3.Database('./helpdesk.db', (err) => {
    if (err) {
        console.error("Database connection error:", err.message);
    }
    console.log('Connected to the helpdesk.db SQLite database.');
});

// Create Users table
db.run(`CREATE TABLE IF NOT EXISTS Users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'agent', 'admin')) DEFAULT 'user'
)`, (err) => {
    if (err) {
        console.error("Error creating Users table:", err.message);
    } else {
        console.log("Users table is ready.");
    }
});

// Create Tickets table (WITH new 'version' and 'due_date' fields)
db.run(`CREATE TABLE IF NOT EXISTS Tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open' CHECK(status IN ('open', 'in_progress', 'closed')),
    priority TEXT NOT NULL DEFAULT 'medium' CHECK(priority IN ('low', 'medium', 'high')) ,
    created_by_user_id INTEGER,
    assigned_to_user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    due_date DATETIME, -- New field for SLA
    version INTEGER DEFAULT 1, -- New field for optimistic locking
    FOREIGN KEY (created_by_user_id) REFERENCES Users (id) ON DELETE SET NULL, -- Added ON DELETE SET NULL
    FOREIGN KEY (assigned_to_user_id) REFERENCES Users (id) ON DELETE SET NULL -- Added ON DELETE SET NULL
)`, (err) => {
    if (err) {
        console.error("Error creating Tickets table:", err.message);
    } else {
        console.log("Tickets table is ready.");
    }
});

// Create Comments table
db.run(`CREATE TABLE IF NOT EXISTS Comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    ticket_id INTEGER,
    user_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES Tickets (id) ON DELETE CASCADE, -- Added ON DELETE CASCADE
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE SET NULL -- Added ON DELETE SET NULL
)`, (err) => {
    if (err) {
        console.error("Error creating Comments table:", err.message);
    } else {
        console.log("Comments table is ready.");
    }
});

// NEW: Create TicketActions table for timeline
db.run(`CREATE TABLE IF NOT EXISTS TicketActions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_id INTEGER NOT NULL,
    user_id INTEGER,
    action TEXT NOT NULL, -- e.g., 'created', 'status_changed', 'assigned', 'commented'
    details TEXT, -- e.g., 'status: open -> in_progress', 'assigned_to: AgentName'
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (ticket_id) REFERENCES Tickets (id) ON DELETE CASCADE, -- Added ON DELETE CASCADE
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE SET NULL -- Added ON DELETE SET NULL
)`, (err) => {
    if (err) {
        console.error("Error creating TicketActions table:", err.message);
    } else {
        console.log("TicketActions table is ready.");
    }
});


// --- Helper to add a timeline action ---
const addTicketAction = (ticket_id, user_id, action, details) => {
    const sql = `INSERT INTO TicketActions (ticket_id, user_id, action, details) VALUES (?, ?, ?, ?)`;
    db.run(sql, [ticket_id, user_id, action, details], (err) => {
        if (err) console.error("Error logging ticket action:", err.message);
    });
};

// --- Helper to calculate SLA status ---
const getSLAStatus = (ticket) => {
    if (ticket.status === 'closed') return 'closed';
    if (!ticket.due_date) return 'no_sla';

    const now = new Date();
    const dueDate = new Date(ticket.due_date);

    if (now > dueDate) {
        return 'breached';
    }

    const diffHours = (dueDate - now) / (1000 * 60 * 60);
    if (diffHours <= 12) { // Within 12 hours
        return 'due_soon';
    }

    return 'on_track';
};


// --- API Endpoints ---
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
        const sql = `INSERT INTO Users (name, username, email, password, role) VALUES (?, ?, ?, ?, ?)`;
        db.run(sql, [name, username, email, hashedPassword, role], function(err) {
            if (err) {
                // Check if the error is due to unique constraint violation
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Username or email already exists' });
                }
                return res.status(500).json({ error: 'Server error during registration: ' + err.message });
            }
            res.status(201).json({ message: 'User created successfully', userId: this.lastID });
        });
    } catch (error) {
        console.error("Registration error:", error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// User Login Endpoint
app.post('/api/login', (req, res) => {
    const { loginIdentifier, password } = req.body;
    if (!loginIdentifier || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }
    const sql = `SELECT * FROM Users WHERE email = ? OR username = ?`;
    db.get(sql, [loginIdentifier, loginIdentifier], async (err, user) => {
        if (err) {
            console.error("Login database error:", err);
            return res.status(500).json({ error: 'Server error during login' });
        }
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        res.status(200).json({ message: 'Login successful', userId: user.id, name: user.name, username: user.username, email: user.email, role: user.role });
    });
});

// Get all users (e.g., for admin assignment). Can filter by role.
app.get('/api/users', (req, res) => {
    const { role } = req.query;
    let sql = `SELECT id, name, email, role FROM Users`;
    const params = [];

    if (role) {
        sql += ` WHERE role = ?`;
        params.push(role);
    }

    db.all(sql, params, (err, users) => {
        if (err) {
            console.error("Error fetching users:", err.message);
            return res.status(500).json({ error: 'Server error fetching users: ' + err.message });
        }
        res.status(200).json({ users });
    });
});


// Get a user's details by ID
app.get('/api/users/:id', (req, res) => {
    const { id } = req.params;
    const sql = `SELECT id, name, username, email, role FROM Users WHERE id = ?`;
    db.get(sql, [id], (err, user) => {
        if (err) {
            console.error("Error fetching user by ID:", err.message);
            return res.status(500).json({ error: 'Server error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.status(200).json({ user });
    });
});


// Update user details (name, username, email, password)
app.patch('/api/users/:id', async (req, res) => {
    const { id } = req.params;
    const { name, username, email, password } = req.body;

    let fieldsToUpdate = [];
    const params = [];

    if (name) {
        fieldsToUpdate.push('name = ?');
        params.push(name);
    }
    if (username) {
        fieldsToUpdate.push('username = ?');
        params.push(username);
    }
    if (email) {
        fieldsToUpdate.push('email = ?');
        params.push(email);
    }
    if (password) {
        try {
            const hashedPassword = await bcrypt.hash(password, 10);
            fieldsToUpdate.push('password = ?');
            params.push(hashedPassword);
        } catch (error) {
            console.error("Error hashing password for user update:", error);
            return res.status(500).json({ error: 'Error hashing new password' });
        }
    }

    if (fieldsToUpdate.length === 0) {
        return res.status(400).json({ error: 'No fields provided for update.' });
    }

    const sql = `UPDATE Users SET ${fieldsToUpdate.join(', ')} WHERE id = ?`;
    params.push(id); // Add user ID to the end of parameters for the WHERE clause

    db.run(sql, params, function(err) {
        if (err) {
            if (err.message.includes('UNIQUE constraint failed')) {
                return res.status(400).json({ error: 'Username or email already taken.' });
            }
            console.error("Failed to update user:", err.message);
            return res.status(500).json({ error: 'Failed to update user: ' + err.message });
        }
        if (this.changes === 0) {
            return res.status(404).json({ error: 'User not found or no changes made.' });
        }
        res.status(200).json({ message: 'User updated successfully' });
    });
});


// Create a new ticket (with priority and due_date calculation)
app.post('/api/tickets', (req, res) => {
    const { title, description, created_by_user_id, priority = 'medium' } = req.body;
    if (!title || !description || !created_by_user_id) {
        return res.status(400).json({ error: 'Title, description, and userId are required' });
    }

    let due_date = null;
    const now = new Date();
    switch (priority) {
        case 'high':
            now.setHours(now.getHours() + 4); // 4 hours for high priority
            due_date = now.toISOString();
            break;
        case 'medium':
            now.setHours(now.getHours() + 24); // 24 hours for medium priority
            due_date = now.toISOString();
            break;
        case 'low':
            now.setDate(now.getDate() + 3); // 3 days for low priority
            due_date = now.toISOString();
            break;
        default:
            due_date = null;
    }

    const sql = `INSERT INTO Tickets (title, description, created_by_user_id, priority, due_date) VALUES (?, ?, ?, ?, ?)`;
    db.run(sql, [title, description, created_by_user_id, priority, due_date], function(err) {
        if (err) {
            console.error("Failed to create ticket:", err.message);
            return res.status(500).json({ error: 'Failed to create ticket: ' + err.message });
        }
        const ticketId = this.lastID;
        addTicketAction(ticketId, created_by_user_id, 'created', `Ticket created with priority: ${priority}`);
        res.status(201).json({ message: 'Ticket created successfully', ticketId });
    });
});

// Get all tickets (with search, filter, pagination, and user-role-based access)
app.get('/api/tickets', (req, res) => {
    const { search, status, priority, breached, limit = 10, offset = 0, userId, role } = req.query;

    let baseSql = `
        SELECT
            t.id,
            t.title,
            t.description,
            t.status,
            t.priority,
            t.created_at,
            t.updated_at,
            t.due_date,
            t.version,
            u.name as creator_name,
            au.name as assigned_agent_name,
            t.created_by_user_id,
            t.assigned_to_user_id
        FROM Tickets t
        LEFT JOIN Users u ON t.created_by_user_id = u.id
        LEFT JOIN Users au ON t.assigned_to_user_id = au.id
    `;
    let countSql = `SELECT COUNT(t.id) as total FROM Tickets t `;

    let whereClauses = [];
    const params = [];
    const countParams = [];

    // Add Joins for countQuery if search involves comments or creator name
    if (search) {
        countSql += `LEFT JOIN Users u ON t.created_by_user_id = u.id `;
        countSql += `LEFT JOIN Comments c ON t.id = c.ticket_id `; // Add comment join for search
    }


    // --- Role-based filtering ---
    if (role === 'user' && userId) {
        whereClauses.push('t.created_by_user_id = ?');
        params.push(userId);
        countParams.push(userId);
    } else if (role === 'agent' && userId) {
        whereClauses.push('(t.assigned_to_user_id = ? OR t.status = "open")'); // Agent sees assigned or open
        params.push(userId);
        countParams.push(userId);
    }
    // Admin sees all tickets, no specific user filter for admin here

    if (status && status !== 'all') {
        whereClauses.push('t.status = ?');
        params.push(status);
        countParams.push(status);
    }
    if (priority && priority !== 'all') {
        whereClauses.push('t.priority = ?');
        params.push(priority);
        countParams.push(priority);
    }
    if (breached === 'true') {
        whereClauses.push('t.status != "closed" AND t.due_date IS NOT NULL AND t.due_date < CURRENT_TIMESTAMP');
    }

    if (search) {
        const searchTerm = `%${search}%`;
        // Search in title, description, creator name, and comments
        whereClauses.push(`(
            t.title LIKE ? OR
            t.description LIKE ? OR
            u.name LIKE ? OR
            EXISTS (SELECT 1 FROM Comments cx WHERE cx.ticket_id = t.id AND cx.content LIKE ?)
        )`);
        params.push(searchTerm, searchTerm, searchTerm, searchTerm);
        countParams.push(searchTerm, searchTerm, searchTerm, searchTerm);
    }

    if (whereClauses.length > 0) {
        baseSql += ' WHERE ' + whereClauses.join(' AND ');
        countSql += ' WHERE ' + whereClauses.join(' AND ');
    }

    // Add DISTINCT to count if join could create duplicates (e.g., searching comments)
    if (search) {
        countSql = `SELECT COUNT(DISTINCT t.id) as total FROM Tickets t
                    LEFT JOIN Users u ON t.created_by_user_id = u.id
                    LEFT JOIN Comments c ON t.id = c.ticket_id ` + (whereClauses.length > 0 ? ' WHERE ' + whereClauses.join(' AND ') : '');
    }

    baseSql += ' GROUP BY t.id ORDER BY t.created_at DESC LIMIT ? OFFSET ?'; // Group by t.id if searching comments to avoid duplicates
    params.push(Number(limit), Number(offset));


    db.all(baseSql, params, (err, rows) => {
        if (err) {
            console.error('Server error fetching tickets:', err.message);
            return res.status(500).json({ error: 'Server error fetching tickets: ' + err.message });
        }

        // Calculate SLA status for each ticket
        const ticketsWithSLA = rows.map(ticket => ({
            ...ticket,
            sla_status: getSLAStatus(ticket)
        }));

        db.get(countSql, countParams, (countErr, countResult) => {
            if (countErr) {
                console.error('Error fetching ticket count:', countErr.message);
                return res.status(500).json({ error: 'Server error fetching ticket count.' });
            }
            const totalTickets = countResult ? countResult.total : 0;
            res.status(200).json({ tickets: ticketsWithSLA, total: totalTickets });
        });
    });
});

// Get a single ticket by ID
app.get('/api/tickets/:id', (req, res) => {
    const { id } = req.params;
    const sql = `
        SELECT
            t.*,
            creator.name as creator_name,
            agent.name as assigned_agent_name
        FROM Tickets t
        LEFT JOIN Users creator ON t.created_by_user_id = creator.id
        LEFT JOIN Users agent ON t.assigned_to_user_id = agent.id
        WHERE t.id = ?`;
    db.get(sql, [id], (err, row) => {
        if (err) {
            console.error("Error fetching single ticket:", err.message);
            return res.status(500).json({ error: 'Server error: ' + err.message });
        }
        if (!row) {
            return res.status(404).json({ error: 'Ticket not found' });
        }
        // Add SLA status
        row.sla_status = getSLAStatus(row);
        res.status(200).json({ ticket: row });
    });
});

// Update a ticket (with optimistic locking and action logging)
app.patch('/api/tickets/:id', async (req, res) => {
    const { id } = req.params;
    const { status, assigned_to_user_id, priority, current_version, user_id: updater_user_id } = req.body;

    if (!updater_user_id) {
        return res.status(400).json({ error: 'User ID of the updater is required.' });
    }

    try {
        const existingTicket = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM Tickets WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                else resolve(row);
            });
        });

        if (!existingTicket) {
            return res.status(404).json({ error: 'Ticket not found.' });
        }

        // Optimistic Locking Check
        if (current_version !== existingTicket.version) {
            return res.status(409).json({ error: 'Conflict: Ticket has been updated by someone else. Please refresh and try again.' });
        }

        let fieldsToUpdate = [];
        const params = [];
        const actions = [];
        let newDueDate = existingTicket.due_date; // Default to existing

        if (status && status !== existingTicket.status) {
            fieldsToUpdate.push('status = ?');
            params.push(status);
            actions.push({ action_type: 'status_changed', details: `status: ${existingTicket.status} -> ${status}` });
        }

        if (priority && priority !== existingTicket.priority) {
            fieldsToUpdate.push('priority = ?');
            params.push(priority);
            actions.push({ action_type: 'priority_changed', details: `priority: ${existingTicket.priority} -> ${priority}` });

            // Recalculate due_date if priority changes
            const now = new Date();
            switch (priority) {
                case 'high': now.setHours(now.getHours() + 4); break;
                case 'medium': now.setHours(now.getHours() + 24); break;
                case 'low': now.setDate(now.getDate() + 3); break;
                default: newDueDate = null; break; // Use null if no specific due date rule
            }
            if (newDueDate !== null) newDueDate = now.toISOString();

            fieldsToUpdate.push('due_date = ?');
            params.push(newDueDate);
        }

        let actualAssignedToUserId = assigned_to_user_id === '' ? null : assigned_to_user_id; // Handle empty string for unassign

        if (actualAssignedToUserId !== existingTicket.assigned_to_user_id) {
            let agentName = 'unassigned';
            if (actualAssignedToUserId) {
                const assignedUser = await new Promise((resolve, reject) => {
                    db.get('SELECT name FROM Users WHERE id = ?', [actualAssignedToUserId], (err, user) => {
                        if (err) reject(err);
                        else resolve(user);
                    });
                });
                if (assignedUser) agentName = assignedUser.name;
            }
            fieldsToUpdate.push('assigned_to_user_id = ?');
            params.push(actualAssignedToUserId);
            actions.push({ action_type: 'assigned', details: `assigned to: ${agentName}` });
        }


        if (fieldsToUpdate.length === 0) {
            return res.status(400).json({ error: 'No meaningful fields to update provided.' });
        }

        fieldsToUpdate.push('version = ?');
        params.push(existingTicket.version + 1);
        fieldsToUpdate.push('updated_at = CURRENT_TIMESTAMP');

        const sql = `UPDATE Tickets SET ${fieldsToUpdate.join(', ')} WHERE id = ?`;
        params.push(id);

        db.run(sql, params, function(err) {
            if (err) {
                console.error('Failed to update ticket DB:', err.message);
                return res.status(500).json({ error: 'Failed to update ticket: ' + err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Ticket not found or no changes made.' });
            }

            actions.forEach(actionObj => {
                addTicketAction(id, updater_user_id, actionObj.action_type, actionObj.details);
            });
            res.status(200).json({ message: 'Ticket updated successfully', newVersion: existingTicket.version + 1 });
        });

    } catch (error) {
        console.error('Error in PATCH /api/tickets/:id:', error);
        res.status(500).json({ error: 'Internal server error: ' + error.message });
    }
});

// Add a comment to a ticket (and log it as an action)
app.post('/api/tickets/:id/comments', (req, res) => {
    const { id: ticket_id } = req.params;
    const { user_id, content } = req.body;
    if (!user_id || !content) {
        return res.status(400).json({ error: 'User ID and content are required' });
    }
    const sql = `INSERT INTO Comments (ticket_id, user_id, content) VALUES (?, ?, ?)`;
    db.run(sql, [ticket_id, user_id, content], function(err) {
        if (err) {
            console.error("Failed to add comment:", err.message);
            return res.status(500).json({ error: 'Failed to add comment: ' + err.message });
        }
        addTicketAction(ticket_id, user_id, 'commented', content);
        res.status(201).json({ message: 'Comment added successfully', commentId: this.lastID });
    });
});

// Get all comments for a specific ticket
app.get('/api/tickets/:id/comments', (req, res) => {
    const { id: ticket_id } = req.params;
    const sql = `
        SELECT
            c.id, c.content, c.created_at, u.name as author_name
        FROM Comments c
        JOIN Users u ON c.user_id = u.id
        WHERE c.ticket_id = ?
        ORDER BY c.created_at ASC`;
    db.all(sql, [ticket_id], (err, rows) => {
        if (err) {
            console.error("Failed to retrieve comments:", err.message);
            return res.status(500).json({ error: 'Failed to retrieve comments: ' + err.message });
        }
        res.status(200).json({ comments: rows });
    });
});

// NEW: Get all actions (timeline) for a specific ticket
app.get('/api/tickets/actions/:id', (req, res) => {
    const { id: ticket_id } = req.params;
    const sql = `
        SELECT
            ta.id, ta.action, ta.details, ta.created_at, u.name as actor_name
        FROM TicketActions ta
        LEFT JOIN Users u ON ta.user_id = u.id
        WHERE ta.ticket_id = ?
        ORDER BY ta.created_at ASC`;
    db.all(sql, [ticket_id], (err, rows) => {
        if (err) {
            console.error("Failed to retrieve ticket actions:", err.message);
            return res.status(500).json({ error: 'Failed to retrieve ticket actions: ' + err.message });
        }
        res.status(200).json({ actions: rows });
    });
});


// Delete a ticket (also deletes associated comments and actions)
app.delete('/api/tickets/:id', (req, res) => {
    const { id } = req.params;
    db.serialize(() => { // Ensure operations run in sequence
        db.run('PRAGMA foreign_keys = ON;'); // Enable foreign key constraints for cascading deletes (ensure your SQLite version supports this and it's truly effective)

        // With ON DELETE CASCADE added to table creation, explicit deletes might not be strictly needed,
        // but it doesn't hurt and adds a layer of robustness if the cascade isn't fully active.
        db.run(`DELETE FROM Comments WHERE ticket_id = ?`, [id], (err) => {
            if (err) console.error("Error deleting comments for ticket:", err.message);
        });
        db.run(`DELETE FROM TicketActions WHERE ticket_id = ?`, [id], (err) => {
            if (err) console.error("Error deleting actions for ticket:", err.message);
        });

        db.run(`DELETE FROM Tickets WHERE id = ?`, [id], function(err) {
            if (err) {
                console.error("Failed to delete ticket:", err.message);
                return res.status(500).json({ error: 'Failed to delete ticket: ' + err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Ticket not found' });
            }
            res.status(200).json({ message: 'Ticket and all associated data deleted successfully' });
        });
    });
});


// Delete a comment (Admin only)
app.delete('/api/comments/:id', (req, res) => {
    const { id: commentId } = req.params;
    const { adminId } = req.query; // Ensure adminId is passed as query param

    if (!adminId) {
        return res.status(400).json({ error: 'Admin ID is required for verification' });
    }
    db.get('SELECT role FROM Users WHERE id = ?', [adminId], (err, user) => {
        if (err || !user) {
            console.error("Error verifying admin for comment delete:", err ? err.message : 'User not found');
            return res.status(400).json({ error: 'Invalid Admin ID or user not found.' });
        }
        if (user.role !== 'admin') {
            return res.status(403).json({ error: 'Forbidden: Only admins can delete comments' });
        }
        db.run(`DELETE FROM Comments WHERE id = ?`, [commentId], function(err) {
            if (err) {
                console.error("Failed to delete comment:", err.message);
                return res.status(500).json({ error: 'Failed to delete comment: ' + err.message });
            }
            if (this.changes === 0) {
                return res.status(404).json({ error: 'Comment not found' });
            }
            res.status(200).json({ message: 'Comment deleted successfully' });
        });
    });
});

app.listen(PORT, '0.0.0.0', () => { // <--- THIS IS THE CRITICAL CHANGE
    console.log(`Server is running on port ${PORT}`); // <--- ALSO UPDATED THIS LOG MESSAGE
});

module.exports = app;