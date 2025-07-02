# Modern Messaging Application

A modern messaging application providing secure, real-time communication with advanced messaging and voice calling features.

## 🚀 Features

- **User Authentication**
  - JWT-based authentication
  - Strong password policy (min. 8 characters, must include special characters)
  - Secure password hashing and storage in PostgreSQL
  - Session expiration management

- **Unique User Identification**
  - UUIDs for consistent and unique user IDs

- **Real-Time Messaging**
  - WebSocket-based instant messaging
  - Message status indicators (sent, delivered, read)
  - Online presence tracking

- **Voice Communication**
  - WebRTC-based voice calls
  - STUN/TURN servers for reliable connectivity
  - Opus codec for high-quality audio
  - Call controls (initiate, accept, reject, terminate)

- **Security**
  - HTTPS support for encrypted web traffic
  - Encrypted credentials and sensitive data storage
  - Secure token handling

## 🛠️ Technologies Used

- Frontend: [Your Frontend Framework] (e.g., React, Vue)
- Backend: [Your Backend Framework] (e.g., Node.js, Django)
- Database: PostgreSQL
- Real-time Communication: WebSocket, WebRTC
- Authentication: JWT
- Audio Codec: Opus
- STUN/TURN: [Your Servers or Services]

## 📦 Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourusername/your-repo-name.git
   cd your-repo-name

2. **Install dependencies**
npm install

## Run the application

   ```bash
   npm start
   #Open the file from a different terminal and type the following and run it
   npx http-server -p 5000 --ssl --cert ./certs/localhost.crt --key ./certs/localhost.key 
