const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');
const https = require('https');
const fs = require('fs');
const { Server } = require('socket.io');

const app = express();

const sslOptions = {
  key: fs.readFileSync('./certs/localhost.key'),
  cert: fs.readFileSync('./certs/localhost.crt'),
};

const server = https.createServer(sslOptions, app);
const io = new Server(server, {
  cors: {
    origin: 'https://localhost:5000',
    methods: ['GET', 'POST'],
    credentials: true,
  },
});

app.use(cors({
  origin: 'https://localhost:5000',
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
app.options('*', cors());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url} from ${req.headers.origin}`);
  console.log('Headers:', req.headers);
  next();
});

app.use(express.json());

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'messaging_app',
  password: '1234',
  port: 5432,
});

const JWT_SECRET = 'your_jwt_secret';

const authenticateToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) {
    console.log('No token provided');
    return res.status(401).json({ message: 'No token provided' });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.error('Invalid token:', err);
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
};

pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  );
  CREATE TABLE IF NOT EXISTS messages (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL,
    recipient_id UUID,
    content TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'sent',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS friends (
    user_id UUID NOT NULL,
    friend_id UUID NOT NULL,
    PRIMARY KEY (user_id, friend_id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (friend_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS friend_requests (
    id UUID PRIMARY KEY,
    sender_id UUID NOT NULL,
    recipient_id UUID NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id),
    UNIQUE (sender_id, recipient_id)
  )
`, (err) => {
  if (err) console.error('Error creating tables:', err);
  else console.log('Tables created successfully');
});

const connectedUsers = new Map();
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('authenticate', (token) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      connectedUsers.set(decoded.userId, socket.id);
      socket.userId = decoded.userId;
      console.log(`User ${decoded.userId} authenticated`);
    } catch (err) {
      console.error('Socket authentication error:', err);
      socket.disconnect();
    }
  });

  socket.on('call_user', ({ recipientId }) => {
    const callerId = socket.userId;
    console.log(`Call initiated from ${callerId} to ${recipientId}`);
    const recipientSocket = connectedUsers.get(recipientId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('incoming_call', { callerId });
    } else {
      socket.emit('error', { message: 'User is offline' });
    }
  });

  socket.on('offer', ({ recipientId, offer }) => {
    console.log(`Offer from ${socket.userId} to ${recipientId}`);
    const recipientSocket = connectedUsers.get(recipientId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('offer', { callerId: socket.userId, offer });
    }
  });

  socket.on('answer', ({ callerId, answer }) => {
    console.log(`Answer from ${socket.userId} to ${callerId}`);
    const callerSocket = connectedUsers.get(callerId);
    if (callerSocket) {
      io.to(callerSocket).emit('answer', { answer });
    }
  });

  socket.on('ice_candidate', ({ recipientId, candidate }) => {
    console.log(`ICE candidate from ${socket.userId} to ${recipientId}`);
    const recipientSocket = connectedUsers.get(recipientId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('ice_candidate', { candidate });
    }
  });

  socket.on('accept_call', ({ callerId }) => {
    console.log(`Call accepted by ${socket.userId} from ${callerId}`);
    const callerSocket = connectedUsers.get(callerId);
    if (callerSocket) {
      io.to(callerSocket).emit('call_accepted', { calleeId: socket.userId });
    }
  });

  socket.on('reject_call', ({ callerId }) => {
    console.log(`Call rejected by ${socket.userId} from ${callerId}`);
    const callerSocket = connectedUsers.get(callerId);
    if (callerSocket) {
      io.to(callerSocket).emit('call_rejected');
    }
  });

  socket.on('end_call', ({ recipientId }) => {
    console.log(`Call ended by ${socket.userId} to ${recipientId}`);
    const recipientSocket = connectedUsers.get(recipientId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('call_ended');
    }
  });

  socket.on('private_message', async ({ recipientId, content }) => {
    const senderId = socket.userId;
    console.log(`Private message from ${senderId} to ${recipientId}`);
    const friendCheck = await pool.query(
      'SELECT 1 FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
      [senderId, recipientId]
    );
    if (friendCheck.rows.length === 0) {
      socket.emit('error', { message: 'Recipient is not your friend' });
      return;
    }

    const messageId = uuidv4();
    try {
      const result = await pool.query(
        'INSERT INTO messages (id, sender_id, recipient_id, content, status) VALUES ($1, $2, $3, $4, $5) RETURNING *',
        [messageId, senderId, recipientId, content, 'sent']
      );
      const message = result.rows[0];
      const recipientSocket = connectedUsers.get(recipientId);
      if (recipientSocket) {
        io.to(recipientSocket).emit('private_message', {
          id: messageId,
          sender_id: senderId,
          recipient_id: recipientId,
          content,
          status: 'delivered',
          timestamp: message.timestamp,
        });
        await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['delivered', messageId]);
      }
      socket.emit('private_message', {
        id: messageId,
        sender_id: senderId,
        recipient_id: recipientId,
        content,
        status: 'sent',
        timestamp: message.timestamp,
      });
      socket.emit('message_status', { id: messageId, status: 'success' });
    } catch (err) {
      console.error('Error sending message:', err);
      socket.emit('error', { message: 'Error sending message' });
    }
  });

  socket.on('group_message', async ({ content }) => {
    const senderId = socket.userId;
    const messageId = uuidv4();
    console.log(`Group message from ${senderId}`);
    try {
      const result = await pool.query(
        'INSERT INTO messages (id, sender_id, content, status) VALUES ($1, $2, $3, $4) RETURNING *',
        [messageId, senderId, content, 'sent']
      );
      const message = result.rows[0];
      io.emit('group_message', {
        id: messageId,
        sender_id: senderId,
        content,
        status: 'delivered',
        timestamp: message.timestamp,
      });
      await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['delivered', messageId]);
      socket.emit('new_message', { id: 'group' });
    } catch (err) {
      console.error('Error sending group message:', err);
      socket.emit('error', { message: 'Error sending group message' });
    }
  });

  socket.on('message', async ({ messageId }) => {
    try {
      await pool.query('UPDATE messages SET status = $1 WHERE id = $2', ['read', messageId]);
      const message = await pool.query('SELECT sender_id FROM messages WHERE id = $1', [messageId]);
      const senderSocketId = connectedUsers.get(message.rows[0].sender_id);
      if (senderSocketId) {
        io.to(senderSocketId).emit('message_status', { id: messageId, status: 'read' });
      }
    } catch (err) {
      console.error('Error updating message status:', err);
    }
  });

  socket.on('disconnect', () => {
    connectedUsers.forEach((value, key) => {
      if (value === socket.id) {
        connectedUsers.delete(key);
      }
    });
    console.log('User disconnected:', socket.id);
  });
});

app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Register attempt for username: ${username}`);
  try {
    const userCheck = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();
    await pool.query(
      'INSERT INTO users (id, username, password) VALUES ($1, $2, $3)',
      [userId, username, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  console.log(`Login attempt for username: ${username}`);
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];
    if (!user) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ message: 'Invalid username or password' });
    }

    const token = jwt.sign({ userId: user.id, iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: '1h' });
    console.log('Generated JWT:', token);
    const decoded = jwt.decode(token);
    console.log('Decoded JWT:', decoded);
    res.json({ token, userId: user.id });
  } catch (err) {
    console.error('Error logging in:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/verify-token', authenticateToken, (req, res) => {
  res.json({ message: 'Token is valid', userId: req.userId });
});

app.get('/api/users/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  console.log(`Fetching user info for userId: ${userId}, by user: ${req.userId}`);
  try {
    const result = await pool.query(
      'SELECT id, username FROM users WHERE id = $1',
      [userId]
    );
    console.log('User fetch result:', result.rows);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/users/search/:username', authenticateToken, async (req, res) => {
  const { username } = req.params;
  console.log(`Searching for username: ${username}, by user: ${req.userId}`);
  try {
    const result = await pool.query(
      'SELECT id, username FROM users WHERE username ILIKE $1 AND id != $2',
      [`%${username}%`, req.userId]
    );
    console.log('Search results:', result.rows);
    res.json(result.rows);
  } catch (err) {
    console.error('Error searching users:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/friends/request', authenticateToken, async (req, res) => {
  const { recipientId } = req.body;
  console.log(`Friend request from ${req.userId} to ${recipientId}`);
  try {
    const userCheck = await pool.query('SELECT 1 FROM users WHERE id = $1', [recipientId]);
    if (userCheck.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (recipientId === req.userId) {
      return res.status(400).json({ message: 'Cannot add yourself as a friend' });
    }
    const existingRequest = await pool.query(
      'SELECT 1 FROM friend_requests WHERE sender_id = $1 AND recipient_id = $2 AND status = $3',
      [req.userId, recipientId, 'pending']
    );
    if (existingRequest.rows.length > 0) {
      return res.status(400).json({ message: 'Friend request already sent' });
    }
    const existingFriend = await pool.query(
      'SELECT 1 FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
      [req.userId, recipientId]
    );
    if (existingFriend.rows.length > 0) {
      return res.status(400).json({ message: 'Already friends' });
    }
    const requestId = uuidv4();
    await pool.query(
      'INSERT INTO friend_requests (id, sender_id, recipient_id, status) VALUES ($1, $2, $3, $4)',
      [requestId, req.userId, recipientId, 'pending']
    );
    const recipientSocket = connectedUsers.get(recipientId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friend_request', { requestId, senderId: req.userId });
    }
    res.json({ message: 'Friend request sent successfully' });
  } catch (err) {
    console.error('Error sending friend request:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/friend_requests', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT fr.id, fr.sender_id, u.username, fr.status, fr.timestamp
       FROM friend_requests fr
       INNER JOIN users u ON fr.sender_id = u.id
       WHERE fr.recipient_id = $1 AND fr.status = $2`,
      [req.userId, 'pending']
    );
    console.log(`Friend requests for user ${req.userId}:`, result.rows);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching friend requests:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/friends/accept', authenticateToken, async (req, res) => {
  const { requestId } = req.body;
  try {
    const requestCheck = await pool.query(
      'SELECT sender_id FROM friend_requests WHERE id = $1 AND recipient_id = $2 AND status = $3',
      [requestId, req.userId, 'pending']
    );
    if (requestCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Friend request not found or already processed' });
    }
    const senderId = requestCheck.rows[0].sender_id;
    await pool.query(
      'UPDATE friend_requests SET status = $1 WHERE id = $2',
      ['accepted', requestId]
    );
    await pool.query(
      'INSERT INTO friends (user_id, friend_id) VALUES ($1, $2), ($2, $1)',
      [req.userId, senderId]
    );
    const senderSocket = connectedUsers.get(senderId);
    if (senderSocket) {
      io.to(senderSocket).emit('friend_request_accepted', { friendId: req.userId });
    }
    const recipientSocket = connectedUsers.get(req.userId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friend_request_accepted', { friendId: senderId });
    }
    res.json({ message: 'Friend request sent successfully' });
  } catch (err) {
    console.error('Error accepting friend request:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/api/friends/reject', async (req, res) => {
  const { requestId } = req.body;
  try {
    const requestCheck = await pool.query(
      'SELECT sender_id FROM friend_requests WHERE id = $1 AND recipient_id = $2 AND status = $3',
      [requestId, req.userId, 'pending']
    );
    if (requestCheck.rows.length === 0) {
      return res.status(404).json({ message: 'Friend request not found or already processed' });
    }
    await pool.query(
      'UPDATE friend_requests SET status = $1 WHERE id = $2',
      ['rejected', requestId]
    );
    const recipientSocket = connectedUsers.get(req.userId);
    if (recipientSocket) {
      io.to(recipientSocket).emit('friend_request_rejected', { requestId });
    }
    res.json({ message: 'Friend request rejected' });
  } catch (err) {
    console.error('Error rejecting friend request:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/friends', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT u.id, u.username FROM users u INNER JOIN friends f ON u.id = f.friend_id WHERE f.user_id = $1',
      [req.userId]
    );
    console.log(`Friends for user ${req.userId}:`, result.rows);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching friends:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

app.get('/api/messages/:userId', authenticateToken, async (req, res) => {
  const { userId } = req.params;
  console.log(`Fetching messages for user: ${req.userId}, target: ${userId}`);
  try {
    if (userId !== 'group') {
      const friendCheck = await pool.query(
        'SELECT 1 FROM friends WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)',
        [req.userId, userId]
      );
      if (friendCheck.rows.length === 0) {
        console.log(`Not friends: ${req.userId} and ${userId}`);
        return res.status(403).json({ message: 'Not friends with this user' });
      }
      const query = userId === 'group'
        ? 'SELECT * FROM messages WHERE recipient_id IS NULL ORDER BY timestamp'
        : 'SELECT * FROM messages WHERE (sender_id = $1 AND recipient_id = $2) OR (sender_id = $2 AND recipient_id = $1) ORDER BY timestamp';
      const params = userId === 'group' ? [] : [req.userId, userId];
      const result = await pool.query(query, params);
      console.log('Messages fetched:', result.rows);
      res.json(result.rows);
    }
  } catch (err) {
    console.error('Error fetching messages:', err);
    res.status(500).json({ message: 'Server error' });
  }
});

server.listen(3000, () => console.log('HTTPS Server running on port 3000'));
