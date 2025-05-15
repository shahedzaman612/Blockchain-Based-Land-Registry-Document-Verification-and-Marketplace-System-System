# Blockchain-Based Land Registry & Marketplace System

This project is a **decentralized land registration and transfer system** built using **Node.js**, **Express**, and a custom **Delegated Proof of Stake (DPoS)**-based blockchain mechanism. It includes a land **marketplace**, **user authentication**, **document hashing**, **zone-wise mining**, **wallet-based payments**, and **real-time chat**.

---

## Features

### 1. **User Roles and Authentication**
- Users can **register** with name, NID, password, and role (`user`, `minar`, or `admin`).
- JWT-based **authentication** system for secure access.
- Role-based page protection (e.g., only `Minars` can access approval pages).

---

### 2. **Land Submission and Verification**
- **Land Submission Page** allows sellers to submit:
  - Seller & Buyer names and NIDs
  - Zone selection (Zone A, B, or C)
  - Land documents: DCR, Porcha, Dolil
- Document files are **hashed** and stored securely.
- Each submission is recorded in `submissions.json`.

---

### 3. **Zone-wise DPoS Mining**
- Each **zone elects one Minar** via **weighted voting** (based on wallet balance).
- Only the elected Minar for a zone can approve submissions and mine blocks.

---

### 4. **Blockchain Block Creation**
- Upon approval, a new block is created containing:
  - Block number, timestamp, hash, previous hash
  - Transaction info: seller/buyer data, land metadata
  - Hashed file paths of uploaded documents
- Block is appended to the `blockchain.json` file.

---

### 5. **Land Marketplace**
- Sellers can **post ads** for land.
- Buyers can **send buy requests** for posted lands.
- Only one buyer can make a request at a time.

---

### 6. **Wallet and Money Transfer**
- Each user has a **wallet** with balance stored in `wallets.json`.
- Buyers must **transfer funds** to sellers before submission is approved.
- Wallets update automatically during successful land transfers.

---

### 7. **Real-Time Chat**
- After a buy request, buyer and seller can **chat in real-time** using **Socket.IO**.
- Includes **message notifications** and chat history.

---

### 8. **Document Hashing**
- Every uploaded document (DCR, Porcha, Dolil) is hashed.
- Ensures **integrity and immutability** of land records.

---

### 9. **User Dashboard**
- Users can view:
  - Their submitted lands
  - Approved blocks
  - Wallet balance
  - Buy request statuses

---

### 10. **Minar Dashboard**
- Minars can view:
  - Pending submissions by zone
  - Approve and mine blocks
  - Voting results for zone leadership

---

### 11. **Admin Features**
- Admin can view all users and manage zone Minar elections.

---

## File Structure

```
/backend
  â”œâ”€â”€ server.js
  â”œâ”€â”€ blockchain.js
  â”œâ”€â”€ users.json
  â”œâ”€â”€ wallets.json
  â”œâ”€â”€ blockchain.json
  â”œâ”€â”€ submissions.json
  â”œâ”€â”€ ads.json
  â”œâ”€â”€ buyRequests.json
  â”œâ”€â”€ notifications.json
  â”œâ”€â”€ zoneMinars.json
  â”œâ”€â”€ uploads/
  â””â”€â”€ chat/
  
/public
  â”œâ”€â”€ index.html
  â”œâ”€â”€ login.html
  â”œâ”€â”€ register.html
  â”œâ”€â”€ submit-land.html
  â”œâ”€â”€ verify.html
  â”œâ”€â”€ create.html
  â”œâ”€â”€ home.html
  â”œâ”€â”€ user-dashboard.html
  â”œâ”€â”€ minar-dashboard.html
  â”œâ”€â”€ post-ad.html
  â”œâ”€â”€ my-lands.html
  â”œâ”€â”€ live-chat.html
  â””â”€â”€ style.css
```

---

## How to Run

1. Install dependencies:  
   `npm install`

2. Run the server:  
   `node server.js`

3. Open `public/index.html` in a browser or serve the frontend with a static server.
