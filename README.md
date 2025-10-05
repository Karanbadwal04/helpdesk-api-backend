# HelpDesk Mini - Hackathon Project

This is the backend API for a minimal helpdesk and ticketing system, built for the hackathon.

---

## Architecture Note

The application follows a standard client-server architecture. The backend is a monolithic RESTful API built with **Node.js** and the **Express.js** framework. It uses a **SQLite** database for data persistence. User authentication is handled via password hashing with **bcrypt**. The API is designed to be consumed by a separate frontend client.

---

## Tech Stack Used

Node.js, Express.js, SQLite, bcrypt, cors

---

## API Endpoint Summary

### Authentication
| Method | Endpoint         | Description                   |
|--------|------------------|-------------------------------|
| `POST` | `/api/register`  | Register a new user.          |
| `POST` | `/api/login`     | Log in an existing user.      |

### Tickets
| Method  | Endpoint               | Description                             |
|---------|------------------------|-----------------------------------------|
| `POST`  | `/api/tickets`         | Create a new ticket.                    |
| `GET`   | `/api/tickets`         | Get a list of all tickets.              |
| `GET`   | `/api/tickets/:id`     | Get details for a single ticket.        |
| `PATCH` | `/api/tickets/:id`     | Update a ticket (status, assignment).   |

### Comments
| Method | Endpoint                    | Description                       |
|--------|-----------------------------|-----------------------------------|
| `POST` | `/api/tickets/:id/comments` | Add a comment to a specific ticket. |

---

## Example Requests

### User Login (`POST /api/login`)
**Request Body:**
```json
{
  "email": "test@example.com",
  "password": "password123"
}