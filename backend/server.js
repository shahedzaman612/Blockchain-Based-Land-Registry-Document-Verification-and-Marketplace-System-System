const express = require("express");
const multer = require("multer");
const http = require("http");
const socketIo = require("socket.io");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const { createBlock, verifyDocument, hashDocument } = require("./blockchain");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // Replace this with an actual secret key in production

// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json()); // Parse JSON request bodies
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve uploaded images from the 'uploads' folder
app.use(express.static(path.join(__dirname, "public"))); // Serve static files from 'public'
const missedNotificationsPath = path.join(__dirname, "notifications.json");
// Initialize multer for file uploads
const upload = multer({ dest: "uploads/" });

// --- JWT Middleware ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, SECRET_KEY, (err, user) => {
      if (err) return res.sendStatus(403); // Forbidden if JWT verification fails
      req.user = user;
      next(); // Proceed to the next middleware/route handler
    });
  } else {
    res.sendStatus(401); // Unauthorized if token is missing
  }
}

function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) return res.sendStatus(403); // Forbidden if role doesn't match
    next();
  };
}

// --- File Helpers ---
const usersFile = path.join(__dirname, "users.json");
const adsFile = path.join(__dirname, "ads.json");

// Read and write user data from/to the 'users.json' file
const readUsers = () =>
  fs.existsSync(usersFile) ? JSON.parse(fs.readFileSync(usersFile)) : [];

const writeUsers = (users) =>
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));

// Read and write ads data from/to the 'ads.json' file
const readAds = () =>
  fs.existsSync(adsFile) ? JSON.parse(fs.readFileSync(adsFile)) : [];

const writeAds = (ads) =>
  fs.writeFileSync(adsFile, JSON.stringify(ads, null, 2));

function loadMissedNotifications() {
  if (fs.existsSync(missedNotificationsPath)) {
    try {
      return JSON.parse(fs.readFileSync(missedNotificationsPath, "utf-8"));
    } catch (err) {
      console.error("Failed to read notification file:", err);
      return [];
    }
  } else {
    return [];
  }
}
const NOTIFICATIONS_FILE = missedNotificationsPath;

function saveNotification(toNID, fromNID, message) {
  const notifications = JSON.parse(
    fs.readFileSync(NOTIFICATIONS_FILE, "utf-8")
  );
  notifications.push({
    to: toNID,
    from: fromNID,
    message,
    timestamp: Date.now(),
    read: false,
  });
  fs.writeFileSync(NOTIFICATIONS_FILE, JSON.stringify(notifications, null, 2));
}
let missedNotifications = loadMissedNotifications();
// Save missed notifications to file
function saveMissedNotifications(data) {
  try {
    fs.writeFileSync(missedNotificationsPath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error("Failed to write notification file:", err);
  }
}
let onlineUsers = {};
// Store socket IDs mapped to NIDs
let usersSockets = {};
// Maps NID -> socket.id

io.on("connection", (socket) => {
  console.log("✅ A user connected");

  socket.on("register", (nid) => {
    if (!nid) return;

    onlineUsers[nid] = socket.id;
    console.log(`Registered user with NID ${nid}`);

    // Check for stored notifications
    const notifications = JSON.parse(
      fs.readFileSync("./notifications.json", "utf-8")
    );
    const userNotifications = notifications.filter(
      (n) => n.to === nid && !n.read
    );

    if (userNotifications.length > 0) {
      socket.emit("pending_notifications", userNotifications);

      // Optionally mark them as read
      const updated = notifications.map((n) =>
        n.to === nid ? { ...n, read: true } : n
      );
      fs.writeFileSync(
        "./notifications.json",
        JSON.stringify(updated, null, 2)
      );
    }
  });

  socket.on("join_room", (room) => {
    socket.join(room);
    console.log(`📥 User joined room ${room}`);
  });

  socket.on("send_message", ({ room, sender, receiver, message }) => {
    const messages = readMessages();
    messages.push({
      room,
      sender,
      to: receiver,
      message,
      timestamp: Date.now(),
    });
    writeMessages(messages);
    io.to(room).emit("receive_message", { sender, message });
  });

  socket.on("chat_notification", ({ from, to }) => {
    const buyerSocketId = onlineUsers[to];
    const notification = {
      to,
      from,
      message: `💬 New chat request from ${from}`,
      timestamp: new Date().toISOString(),
    };

    // 1. Save to notifications.json
    const filePath = missedNotificationsPath;

    let notifications = [];

    try {
      if (fs.existsSync(filePath)) {
        notifications = JSON.parse(fs.readFileSync(filePath));
      }
    } catch (err) {
      console.error("❌ Error reading notifications:", err);
    }

    notifications.push(notification);

    try {
      fs.writeFileSync(filePath, JSON.stringify(notifications, null, 2));
      console.log("✅ Notification saved to file.");
    } catch (err) {
      console.error("❌ Error writing notification:", err);
    }

    // 2. Emit real-time notification to buyer
    if (buyerSocketId) {
      io.to(buyerSocketId).emit("chat_notification", { from });
      console.log(`📢 Notification sent to buyer with NID ${to}`);
    } else {
      console.log(`❌ Buyer with NID ${to} is not online.`);
    }
  });
  socket.on("set-nid", (nid) => {
    // Store the user's socket ID with their NID
    usersSockets[nid] = socket.id;
    console.log(`Socket ID for NID ${nid}: ${socket.id}`);
  });
  socket.on("disconnect", () => {
    for (let nid in onlineUsers) {
      if (onlineUsers[nid] === socket.id) {
        delete onlineUsers[nid];
        console.log(`👋 User with NID ${nid} disconnected.`);
        break;
      }
    }
    for (let nid in usersSockets) {
      if (usersSockets[nid] === socket.id) {
        delete usersSockets[nid];
        console.log(`User with NID ${nid} disconnected`);
        break;
      }
    }
  });
});
// --- Routes ---

// Serve Home Page
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// --- Modified Register Route ---
app.post("/register", async (req, res) => {
  try {
    const { username, nid, password, role } = req.body;

    if (!nid || nid.length < 5) {
      return res.status(400).json({ message: "Invalid NID number" });
    }

    const users = readUsers();
    if (users.find((u) => u.nid === nid)) {
      return res.status(400).json({ message: "NID already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({
      username,
      nid,
      password: hashedPassword,
      role: role || "user",
    });
    writeUsers(users);
    res.status(201).json({ message: "User registered successfully!" });
  } catch (err) {
    console.error("Register error:", err);
    res.status(500).json({ message: "Server Error" });
  }
});

// --- Modified Login Route ---
app.post("/login", async (req, res) => {
  try {
    const { nid, password } = req.body;

    const users = readUsers();
    const user = users.find((u) => u.nid === nid);
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ message: "Invalid NID or password" });
    }

    const token = jwt.sign(
      {
        nid: user.nid,
        username: user.username,
        role: user.role,
      },
      SECRET_KEY,
      { expiresIn: "2h" }
    );

    // ✅ Return token, nid, and role
    res.json({
      token,
      nid: user.nid,
      role: user.role,
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server Error" });
  }
});

// Route for creating a new block
// Create Block Route
const crypto = require("crypto"); // Make sure this is at the top

// Create Block Route
app.post(
  "/create-block",
  authenticateJWT,
  authorizeRole("admin"),
  upload.fields([{ name: "dcr" }, { name: "porcha" }, { name: "dolil" }]), // Handle multiple files
  (req, res) => {
    try {
      const { fromAddress, toAddress, fromNID, toNID, nonce } = req.body;

      if (
        !req.files?.dcr?.[0] ||
        !req.files?.porcha?.[0] ||
        !req.files?.dolil?.[0]
      ) {
        return res.status(400).json({ message: "All documents are required." });
      }

      // Auto-generate a unique transaction ID
      const transactionId = crypto
        .createHash("sha256")
        .update(Date.now() + Math.random().toString())
        .digest("hex")
        .substring(0, 12); // shorten for readability

      const block = createBlock({
        transactionId,
        from: fromAddress,
        fromNID,
        to: toAddress,
        toNID,
        nonce,
        docs: {
          dcr: req.files["dcr"][0].path,
          porcha: req.files["porcha"][0].path,
          dolil: req.files["dolil"][0].path,
        },
      });

      res.json({ message: "Block created successfully!", block });
    } catch (err) {
      console.error("Create block error:", err);
      res.status(500).json({ message: "Failed to create block" });
    }
  }
);

// View All Blocks (Admin)
app.get("/blocks", authenticateJWT, authorizeRole("admin"), (req, res) => {
  const { blockchain } = require("./blockchain");
  res.json(blockchain);
});

// Verify Document Route
app.post(
  "/verify-document",
  authenticateJWT,
  upload.single("document"), // Single document upload
  (req, res) => {
    try {
      const { docType } = req.body;
      const filePath = req.file?.path;
      if (!filePath) return res.status(400).json({ message: "File required" });

      const fileHash = hashDocument(filePath);
      const block = verifyDocument(fileHash, docType);

      if (block) {
        res.json({ authentic: true, block });
      } else {
        res.json({ authentic: false });
      }
    } catch (err) {
      console.error("Verification error:", err);
      res.status(500).json({ message: "Verification failed" });
    }
  }
);

// Post Ad Route
app.post("/post-ad", authenticateJWT, upload.single("image"), (req, res) => {
  try {
    const { title, price, description } = req.body;
    const imagePath = req.file?.path;
    if (!imagePath) return res.status(400).json({ message: "Image required" });

    const newAd = {
      id: Date.now(),
      title,
      price,
      description,
      imagePath: `/uploads/${path.basename(imagePath)}`,
      postedBy: req.user.username,
      sellerNID: req.user.nid, // <-- Added NID here
    };

    const ads = readAds();
    ads.push(newAd);
    writeAds(ads);

    res.status(201).json({ message: "Ad posted successfully!", ad: newAd });
  } catch (err) {
    console.error("Ad post error:", err);
    res.status(500).json({ message: "Failed to post ad" });
  }
});

// Get Ads Route
app.get("/ads", authenticateJWT, (req, res) => {
  try {
    const ads = readAds().map((ad) => ({
      ...ad,
      imageUrl: `http://localhost:${PORT}${ad.imagePath}`, // Serve the full image URL
    }));
    res.json(ads);
  } catch (err) {
    console.error("Read ads error:", err);
    res.status(500).json({ message: "Failed to fetch ads" });
  }
});

// Get All Users (Admin)
app.get("/users", authenticateJWT, authorizeRole("admin"), (req, res) => {
  const users = readUsers();
  const safeUsers = users.map((u) => ({
    username: u.username,
    role: u.role,
  }));
  res.json(safeUsers);
});
const BUY_REQUESTS_FILE = path.join(__dirname, "buyRequests.json");
const ADS_FILE = path.join(__dirname, "ads.json");

// Helper to read/write buyRequests
function readBuyRequests() {
  if (!fs.existsSync(BUY_REQUESTS_FILE)) return [];
  return JSON.parse(fs.readFileSync(BUY_REQUESTS_FILE));
}

function writeBuyRequests(data) {
  fs.writeFileSync(BUY_REQUESTS_FILE, JSON.stringify(data, null, 2));
}
// Function to get socket ID by NID
function getSocketIdByNID(nid) {
  return usersSockets[nid];
}

app.get("/buy-requests", authenticateJWT, (req, res) => {
  try {
    const sellerNID = req.user.nid; // ✅ Declare it with `const`
    console.log("Fetching buy requests for seller NID:", sellerNID);

    const allRequests = readBuyRequests();
    console.log(allRequests); // ✅ Read all buy requests
    const sellerRequests = allRequests.filter(
      (request) => request.sellerNID === sellerNID
    );

    res.json(sellerRequests);
  } catch (err) {
    console.error("Error fetching buy requests:", err);
    res.status(500).json({ message: "Server error" });
  }
});
app.post("/buy-request/:adId", authenticateJWT, (req, res) => {
  try {
    const adId = req.params.adId;
    const buyerUsername = req.user.username;
    const buyerNID = req.user.nid; // ✅ Get buyer's NID from token

    console.log(
      `Received Buy Request: adId: ${adId}, Buyer: ${buyerUsername}, NID: ${buyerNID}`
    );

    // Read ads data
    let ads;
    try {
      ads = JSON.parse(fs.readFileSync(ADS_FILE));
    } catch (err) {
      console.error("Error reading ADS_FILE:", err);
      return res.status(500).json({ message: "Error reading ads file" });
    }

    const ad = ads.find((ad) => ad.id == adId);

    if (!ad) {
      console.error(`Ad with ID ${adId} not found.`);
      return res.status(404).json({ message: "Ad not found" });
    }

    // Create the new buy request
    const newRequest = {
      adId: ad.id,
      adTitle: ad.title,
      sellerNID: ad.sellerNID, // Optional if stored in ad
      buyerUsername,
      buyerNID,
      timestamp: new Date().toISOString(),
      message: `A buyer is interested in your land ad: "${ad.title}".`,
    };

    // Save the new request
    const allRequests = readBuyRequests(); // Function to read from buyRequests.json
    allRequests.push(newRequest);
    writeBuyRequests(allRequests); // Save updated requests to buyRequests.json

    // Emit a notification to the seller via socket
    const sellerSocketId = getSocketIdByNID(ad.sellerNID);
    if (sellerSocketId) {
      io.to(sellerSocketId).emit("buy_request_notification", newRequest); // Emit the notification to seller
    }

    res.json({ message: "Buy request submitted successfully" });
  } catch (err) {
    console.error("Buy request error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// GET: Fetch Buy Requests for a Seller

// Fetch Messages for Logged-in User
app.get("/messages", authenticateJWT, (req, res) => {
  try {
    const messagesFile = path.join(__dirname, "messages.json");
    const messages = fs.existsSync(messagesFile)
      ? JSON.parse(fs.readFileSync(messagesFile))
      : [];

    // Filter messages where the logged-in user is the receiver
    const userMessages = messages.filter(
      (message) => message.to === req.user.username
    );

    res.json(userMessages);
  } catch (err) {
    console.error("Error fetching messages:", err);
    res.status(500).json({ message: "Failed to fetch messages" });
  }
});

// /my-lands route: Fetch blocks where user is the buyer (toNID)
app.get("/my-lands", authenticateJWT, (req, res) => {
  try {
    const buyerNID = req.user.nid;
    const { blockchain } = require("./blockchain");

    const myBlocks = blockchain.filter((block) => block.toNID === buyerNID);
    res.json(myBlocks);
  } catch (err) {
    console.error("Error fetching user lands:", err);
    res.status(500).json({ message: "Failed to fetch land records" });
  }
});
app.get("/notifications", authenticateJWT, (req, res) => {
  try {
    const nid = req.user.nid;
    const notifications = loadMissedNotifications();
    const userNotifications = notifications.filter(
      (n) => n.to === nid && !n.read
    );

    res.json(userNotifications);
  } catch (err) {
    console.error("Notification fetch error:", err);
    res.status(500).json({ message: "Failed to load notifications" });
  }
});
const CHAT_FILE = path.join(__dirname, "chatMessages.json");

function readMessages() {
  return fs.existsSync(CHAT_FILE) ? JSON.parse(fs.readFileSync(CHAT_FILE)) : [];
}

function writeMessages(messages) {
  fs.writeFileSync(CHAT_FILE, JSON.stringify(messages, null, 2));
}

// Get chat history between two users
app.get("/messages/:nid1/:nid2", authenticateJWT, (req, res) => {
  const { nid1, nid2 } = req.params;
  const allMessages = readMessages();
  const chat = allMessages.filter(
    (msg) =>
      (msg.from === nid1 && msg.to === nid2) ||
      (msg.from === nid2 && msg.to === nid1)
  );
  res.json(chat);
});
//Start the server
// app.listen(PORT, () => {
//   console.log(`Server is running on http://localhost:${PORT}`);
// });
// app.get("/get-user/:nid", (req, res) => {
//   const { nid } = req.params;
//   const users = JSON.parse(fs.readFileSync("users.json", "utf-8"));
//   const user = users.find((u) => u.nid === nid);
//   if (user) {
//     res.json({ username: user.username });
//   } else {
//     res.status(404).json({ error: "User not found" });
//   }
// });

server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});
