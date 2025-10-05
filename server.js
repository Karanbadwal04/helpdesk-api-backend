const express = require('express');
const dotenv = require('dotenv').config(); // Load environment variables
const colors = require('colors'); // For colorful console output

const app = express();
const PORT = process.env.PORT || 5000; // Use port from environment or default to 5000

// Basic route
app.get('/', (req, res) => {
    res.status(200).json({ message: 'Welcome to the Helpdesk API!' });
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`.yellow.bold));