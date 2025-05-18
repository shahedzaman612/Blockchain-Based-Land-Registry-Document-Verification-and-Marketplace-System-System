const express = require("express");
const multer = require("multer");
const http = require("http");
const socketIo = require("socket.io");
const fs = require("fs");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();
const users = JSON.parse(fs.readFileSync("users.json"));

const {
  createBlock,
  calculateHash,
  verifyDocument,
  hashDocument,
} = require("./blockchain");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json()); // Parse JSON request bodies
app.use("/uploads", express.static(path.join(__dirname, "uploads")));
app.use(express.static(path.join(__dirname, "public")));
const missedNotificationsPath = path.join(__dirname, "notifications.json");
// Initialize multer for file uploads
const upload = multer({ dest: "uploads/" });
// loadJSON function to read JSON files
function loadJSON(path) {
  try {
    const data = fs.readFileSync(path);
    return JSON.parse(data);
  } catch (err) {
    console.error(`Error reading ${path}:`, err);
    return [];
  }
}
// --- JWT Middleware ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
      if (err) return res.sendStatus(403);
      req.user = user;
      next();
    });
  } else {
    res.sendStatus(401);
  }
}

function authorizeRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.sendStatus(403); // Forbidden
    }
    next();
  };
}

function getUsernameFromNID(nid) {
  const user = users.find((u) => u.nid === nid);
  return user ? user.username : nid;
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
function getUsernameFromNID(nid) {
  const user = users.find((u) => u.nid === nid);
  return user ? user.username : nid;
}
const MESSAGES_FILE = path.join(__dirname, "messages.json");

function loadMessages() {
  try {
    if (fs.existsSync(MESSAGES_FILE)) {
      const data = fs.readFileSync(MESSAGES_FILE);
      return JSON.parse(data);
    } else {
      return {};
    }
  } catch (err) {
    console.error("Error loading messages:", err);
    return {};
  }
}

function saveMessages(messages) {
  try {
    fs.writeFileSync(MESSAGES_FILE, JSON.stringify(messages, null, 2));
  } catch (err) {
    console.error("Error saving messages:", err);
  }
}
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

  socket.on("send_message", ({ room, sender, message }) => {
    const senderUsername = getUsernameFromNID(sender);

    // Save to messages.json
    const allMessages = loadMessages();
    allMessages.push({
      room,
      senderNID: sender,
      senderUsername,
      message,
      timestamp: new Date().toISOString(),
    });
    saveMessages(allMessages);

    // Emit to clients
    io.to(room).emit("receive_message", {
      senderUsername,
      senderNID: sender,
      message,
    });
  });

  socket.on("chat_notification", ({ from, to }) => {
    const buyerSocketId = onlineUsers[to];
    const fromUsername = getUsernameFromNID(from);

    const notification = {
      to,
      from,
      fromUsername,
      message: `💬 New chat request from ${fromUsername}`,
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
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

//--- Register Route ---
app.post("/register", async (req, res) => {
  try {
    const { username, nid, password, role, zone } = req.body;

    // Basic validation
    if (!nid || nid.length < 5) {
      return res.status(400).json({ message: "Invalid NID number" });
    }
    if (!zone) {
      return res.status(400).json({ message: "Zone is required" });
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
      role: role || "user", // user or minar
      zone,
      wallet: 10000, // 💰 Starting wallet balance
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
      JWT_SECRET,
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

// Create Block Route
const crypto = require("crypto");

// Create Block Route
app.post(
  "/create-block",
  authenticateJWT,
  authorizeRole("admin"),
  upload.fields([{ name: "dcr" }, { name: "porcha" }, { name: "dolil" }]),
  (req, res) => {
    try {
      const { fromAddress, toAddress, fromNID, toNID, zone } = req.body;

      if (
        !req.files?.dcr?.[0] ||
        !req.files?.porcha?.[0] ||
        !req.files?.dolil?.[0]
      ) {
        return res.status(400).json({ message: "All documents are required." });
      }

      // Check if the logged-in Minar is elected for the zone
      const zoneMinars = JSON.parse(fs.readFileSync("zoneMinars.json"));
      if (zoneMinars[zone] !== req.user.nid) {
        return res
          .status(403)
          .json({ message: "You are not the elected Minar for this zone." });
      }

      // Auto-generate a unique transaction ID
      const transactionId = crypto
        .createHash("sha256")
        .update(Date.now() + Math.random().toString())
        .digest("hex")
        .substring(0, 12); // shorten for readability
      const nonce = crypto
        .createHash("sha256")
        .update(Date.now() + Math.random().toString())
        .digest("int")
        .substring(0, 3);

      const block = createBlock({
        transactionId,
        from: fromAddress,
        fromNID,
        to: toAddress,
        toNID,
        nonce,
        zone,
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
app.get(
  "/blocks",
  authenticateJWT,
  authorizeRole("admin", "miner"),
  (req, res) => {
    const { blockchain } = require("./blockchain");
    res.json(blockchain);
  }
);

// Verify Document Route
app.post(
  "/verify-document",
  authenticateJWT,
  upload.single("document"),
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
    const { title, price, description, posterName } = req.body;
    const imagePath = req.file?.path;
    if (!imagePath) return res.status(400).json({ message: "Image required" });

    const newAd = {
      id: Date.now(),
      title,
      price,
      description,
      imagePath: `/uploads/${path.basename(imagePath)}`,
      postedBy: req.user.username,
      sellerNID: req.user.nid,
      displayName: posterName || req.user.username, // 👈 Only used for display
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
      imageUrl: `http://localhost:${PORT}${ad.imagePath}`,
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
    const sellerNID = req.user.nid;
    const allRequests = readBuyRequests();

    const sellerRequests = allRequests
      .filter((request) => request.sellerNID === sellerNID)
      .map((request) => ({
        ...request,
        buyerUsername: getUsernameFromNID(request.buyerNID),
      }));

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
    const buyerNID = req.user.nid;

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
      sellerNID: ad.sellerNID,
      buyerUsername,
      buyerNID,
      timestamp: new Date().toISOString(),
      message: `A buyer is interested in your land ad: "${ad.title}".`,
    };

    // Save the new request
    const allRequests = readBuyRequests();
    allRequests.push(newRequest);
    writeBuyRequests(allRequests);

    // Emit a notification to the seller via socket
    const sellerSocketId = getSocketIdByNID(ad.sellerNID);
    if (sellerSocketId) {
      io.to(sellerSocketId).emit("buy_request_notification", newRequest);
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

app.get("/chat-history", (req, res) => {
  const room = req.query.room;
  const messages = loadMessages().filter((msg) => msg.room === room);
  res.json(messages);
});
app.get("/get-user-info", (req, res) => {
  const nid = req.query.nid;

  if (!nid) {
    return res.status(400).json({ error: "Missing NID parameter" });
  }

  const users = loadJSON("users.json");
  const user = users.find((u) => u.nid === nid);

  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  res.json({
    username: user.username,
    profilePic: user.profilePic || null,
  });
});
function getUserNameByNID(partnerNID) {
  const users = JSON.parse(fs.readFileSync("users.json"));
  const user = users.find((u) => u.nid.toString() === nid.toString());
  return user ? user.name : null;
}
app.get("/chat-rooms", authenticateJWT, (req, res) => {
  const userId = req.user?.nid?.toString();

  if (!userId) {
    return res.status(401).json({ error: "Invalid or missing user data" });
  }

  const messages = JSON.parse(fs.readFileSync("messages.json"));

  const rooms = new Set();
  const partners = {};

  messages.forEach((msg) => {
    const [id1, id2] = msg.room.split("-");
    if (id1 === userId || id2 === userId) {
      rooms.add(msg.room);

      const partnerNID = id1 === userId ? id2 : id1;

      partners[msg.room] = getUsernameFromNID(partnerNID);
    }
  });

  const chatRooms = Array.from(rooms).map((room) => ({
    room,
    partnerName: partners[room] || "Unknown",
  }));

  res.json({ chatRooms });
});

app.post("/remove-buy-request", authenticateJWT, (req, res) => {
  const { buyerNID, sellerNID } = req.body;

  if (!buyerNID || !sellerNID) {
    return res.status(400).json({ message: "Missing buyer or seller NID" });
  }

  let buyRequests = JSON.parse(fs.readFileSync("buyRequests.json"));
  buyRequests = buyRequests.filter(
    (r) => !(r.buyerNID === buyerNID && r.sellerNID === sellerNID)
  );

  fs.writeFileSync("buyRequests.json", JSON.stringify(buyRequests, null, 2));
  res.json({ message: "Buy request removed" });
});
app.post(
  "/submit-land",
  authenticateJWT, // Ensure the user is authenticated
  authorizeRole("user"), // Only users with "user" role can submit land info
  upload.fields([{ name: "dcr" }, { name: "porcha" }, { name: "dolil" }]), // Handle file uploads
  (req, res) => {
    try {
      // Extract data
      const { fromAddress, toAddress, fromNID, toNID, zone } = req.body;

      // Validate required fields
      if (!fromAddress || !toAddress || !fromNID || !toNID || !zone) {
        return res
          .status(400)
          .json({ message: "All fields including zone are required." });
      }

      // Validate required documents
      if (
        !req.files?.dcr?.[0] ||
        !req.files?.porcha?.[0] ||
        !req.files?.dolil?.[0]
      ) {
        return res.status(400).json({ message: "All documents are required." });
      }

      // Create the submission object
      const submission = {
        id: crypto.randomUUID(),
        from: fromAddress,
        fromNID,
        to: toAddress,
        toNID,
        zone,
        docs: {
          dcr: req.files["dcr"][0].path,
          porcha: req.files["porcha"][0].path,
          dolil: req.files["dolil"][0].path,
        },
        status: "pending",
        submittedBy: req.user.username,
        submittedAt: new Date().toISOString(),
      };

      // Load existing submissions
      let submissions = [];
      try {
        const data = fs.readFileSync("submissions.json", "utf-8");
        submissions = data ? JSON.parse(data) : [];
      } catch (err) {
        console.warn("Error reading submissions.json, creating a new one.");
      }

      // Add new submission
      submissions.push(submission);

      // Ensure uploads folder exists
      if (!fs.existsSync("uploads")) {
        fs.mkdirSync("uploads");
      }

      // Save updated submissions
      fs.writeFileSync(
        "submissions.json",
        JSON.stringify(submissions, null, 2)
      );

      res.json({ message: "Submission successful", submission });
    } catch (err) {
      console.error("Land submission error:", err.stack || err);
      res
        .status(500)
        .json({ message: "Failed to submit land info", error: err.message });
    }
  }
);
app.get(
  "/pending-submissions",
  authenticateJWT,
  authorizeRole("miner"),
  (req, res) => {
    try {
      const submissions = JSON.parse(
        fs.readFileSync("submissions.json", "utf-8")
      );

      const transfers = JSON.parse(fs.readFileSync("transfers.json", "utf-8"));

      const users = JSON.parse(fs.readFileSync("users.json", "utf-8"));
      const zoneMinars = JSON.parse(
        fs.readFileSync("zoneMinars.json", "utf-8")
      );

      const currentUser = users.find((u) => u.nid === req.user.nid);
      if (!currentUser) {
        return res.status(403).json({ message: "User not found" });
      }

      const userZone = currentUser.zone;
      const electedMinarNID = zoneMinars[userZone];

      if (electedMinarNID !== currentUser.nid) {
        return res.status(403).json({
          message: "⛔ You are not the elected Minar for your zone.",
        });
      }

      const zoneSubmissions = submissions
        .filter((s) => s.status === "pending" && s.zone === userZone)
        .map((s) => {
          const lastTx = transfers
            .filter((tx) => tx.toNID === s.fromNID)
            .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))[0];

          return {
            ...s,
            lastTransaction: lastTx || null,
          };
        });

      res.json(zoneSubmissions);
    } catch (err) {
      console.error("Error in /pending-submissions:", err);
      res.status(500).json({ message: "Failed to load submissions" });
    }
  }
);
function writeJSON(filePath, data) {
  try {
    const jsonData = JSON.stringify(data, null, 2); // Pretty format
    fs.writeFileSync(path.resolve(filePath), jsonData, "utf8");
    console.log(`✅ Successfully written to ${filePath}`);
  } catch (error) {
    console.error(`❌ Failed to write to ${filePath}:`, error);
  }
}
app.post("/approve-submission/:id", authenticateJWT, (req, res) => {
  const submissionId = req.params.id;
  const user = req.user;

  if (user.role !== "miner") {
    return res.status(403).json({ message: "Only Minars can approve blocks" });
  }

  const submissions = loadJSON("submissions.json");
  const submissionIndex = submissions.findIndex((s) => s.id === submissionId);

  if (submissionIndex === -1) {
    return res.status(404).json({ message: "Submission not found" });
  }

  const submission = submissions[submissionIndex];
  const zoneMinars = JSON.parse(fs.readFileSync("zoneMinars.json"));
  if (zoneMinars[submission.zone] !== req.user.nid) {
    return res
      .status(403)
      .json({ message: "You are not the elected Minar for this zone." });
  }

  const transfers = loadJSON("transfers.json");
  const relevantTransfers = transfers
    .filter(
      (t) => t.fromNID === submission.toNID && t.toNID === submission.fromNID
    )
    .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

  const lastTransfer = relevantTransfers[0];
  if (!lastTransfer || lastTransfer.amount <= 0) {
    return res.status(400).json({
      message:
        "Money transfer not found. Buyer must transfer funds before approval.",
    });
  }

  // Auto-generate a unique transaction ID
  const transactionId = crypto
    .createHash("sha256")
    .update(Date.now() + Math.random().toString())
    .digest("hex")
    .substring(0, 12); // shorten for readability

  const nonce = crypto
    .createHash("sha256")
    .update(Date.now() + Math.random().toString())
    .digest("hex")
    .substring(0, 3);

  createBlock({
    transactionId: transactionId,
    from: submission.from,
    fromNID: submission.fromNID,
    to: submission.to,
    toNID: submission.toNID,
    nonce: nonce,
    zone: submission.zone,
    docs: submission.docs,
  });

  submissions.splice(submissionIndex, 1);
  writeJSON("submissions.json", submissions);

  res.status(200).json({
    message: "✅ Block approved and added to blockchain.",
    includedTransfer: lastTransfer,
  });
});

app.post(
  "/reject-submission/:id",
  authenticateJWT,
  authorizeRole("miner", "admin"),
  (req, res) => {
    const id = req.params.id;
    let submissions = JSON.parse(fs.readFileSync("submissions.json", "utf-8"));
    const index = submissions.findIndex((s) => s.id === id);

    if (index === -1) {
      return res.status(404).json({ message: "Submission not found" });
    }

    submissions[index].status = "rejected";
    fs.writeFileSync("submissions.json", JSON.stringify(submissions, null, 2));
    res.json({ message: "Submission rejected" });
  }
);

const walletFilePath = path.join(__dirname, "transfers.json");

function readWallets() {
  if (!fs.existsSync(walletFilePath)) return {};
  return JSON.parse(fs.readFileSync(walletFilePath, "utf-8"));
}

function writeWallets(wallets) {
  fs.writeFileSync(walletFilePath, JSON.stringify(wallets, null, 2));
}

app.get("/wallet", authenticateJWT, (req, res) => {
  const users = readUsers();
  const transfers = readTransfers();
  const user = users.find((u) => u.nid === req.user.nid);

  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  const transactions = transfers.filter(
    (t) => t.fromNID === user.nid || t.toNID === user.nid
  );

  res.json({
    nid: user.nid,
    balance: user.wallet,
    transactions,
  });
});

const transfersPath = path.join(__dirname, "transfers.json");

function readTransfers() {
  if (!fs.existsSync(transfersPath)) return [];
  return JSON.parse(fs.readFileSync(transfersPath));
}

function writeTransfers(data) {
  fs.writeFileSync(transfersPath, JSON.stringify(data, null, 2));
}

// Transfer route with logging
app.post("/transfer-money", authenticateJWT, (req, res) => {
  const { fromNID, toNID, amount } = req.body;
  const users = readUsers();

  const fromUser = users.find((u) => u.nid === fromNID);
  const toUser = users.find((u) => u.nid === toNID);

  if (!fromUser || !toUser) {
    return res.status(404).json({ message: "User(s) not found" });
  }

  if (fromUser.wallet < amount) {
    return res.status(400).json({ message: "Insufficient balance" });
  }

  fromUser.wallet -= amount;
  toUser.wallet += amount;

  writeUsers(users);

  // Log the transfer
  const transfers = readTransfers();
  const newTransfer = {
    id: Date.now(),
    fromNID,
    fromUser: fromUser.username,
    toNID,
    toUser: toUser.username,
    amount,
    timestamp: new Date().toISOString(),
  };
  transfers.push(newTransfer);
  writeTransfers(transfers);

  // Prepare receipt
  const receipt = {
    transactionId: `TX-${newTransfer.id}`,
    from: {
      nid: fromUser.nid,
      name: fromUser.username,
    },
    to: {
      nid: toUser.nid,
      name: toUser.username,
    },
    amount,
    timestamp: newTransfer.timestamp,
  };

  res.json({
    message: `✅ Transferred ${amount} BDT from ${fromUser.username} to ${toUser.username}`,
    fromBalance: fromUser.wallet,
    toBalance: toUser.wallet,
    transfer: newTransfer,
    receipt, // ✅ Send the receipt
  });
});

app.get("/all-transfers", authenticateJWT, (req, res) => {
  const transfers = JSON.parse(fs.readFileSync("transfers.json"));
  res.json(transfers);
});
app.get("/receipt/:id", authenticateJWT, (req, res) => {
  const transfers = readTransfers();
  const transfer = transfers.find((t) => t.id == req.params.id);

  if (!transfer) {
    return res.status(404).send("Receipt not found");
  }

  // Check if user is part of this transaction
  if (transfer.fromNID !== req.user.nid && transfer.toNID !== req.user.nid) {
    return res.status(403).send("Unauthorized");
  }

  const receipt = `
    Transaction Receipt
    -------------------------
    ID: ${transfer.id}
    From: ${transfer.fromUser} (NID: ${transfer.fromNID})
    To: ${transfer.toUser} (NID: ${transfer.toNID})
    Amount: ${transfer.amount} BDT
    Timestamp: ${new Date(transfer.timestamp).toLocaleString()}
    -------------------------
    Thank you for using our wallet system.
  `;

  res.setHeader("Content-Type", "text/plain");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename=receipt-${transfer.id}.txt`
  );
  res.send(receipt);
});
const { castVote, tallyVotes, readVotes } = require("./minarVotes");
// Get current votes (optional debug or admin tool)
app.get("/votes", authenticateJWT, authorizeRole("admin"), (req, res) => {
  res.json(readVotes());
});
app.get("/user", authenticateJWT, authorizeRole("user"), (req, res) => {
  const users = readUsers();
  const currentUser = users.find((u) => u.nid === req.user.nid);

  if (!currentUser || currentUser.role !== "user") {
    return res.status(403).json({ message: "Only users can vote" });
  }

  const zone = currentUser.zone;
  const minars = users.filter((u) => u.role === "miner" && u.zone === zone);

  res.json(minars);
});

// Utility function to check if voting is still open
function isVotingOpen() {
  const votingPeriod = JSON.parse(
    fs.readFileSync("votingPeriod.json", "utf-8")
  );
  const now = new Date();
  return (
    now >= new Date(votingPeriod.startDate) &&
    now <= new Date(votingPeriod.endDate)
  );
}

// User votes for Minar
app.post("/vote-minar", authenticateJWT, (req, res) => {
  const { votedMinarNID } = req.body;

  let period;
  try {
    period = JSON.parse(fs.readFileSync("votingPeriod.json", "utf-8"));
  } catch (err) {
    return res.status(500).json({ message: "Voting period not set" });
  }

  const now = new Date();
  const start = new Date(period.start);
  const end = new Date(period.end);

  if (now < start || now > end) {
    return res.status(403).json({ message: "⛔ Voting is currently closed." });
  }

  const result = castVote(req.user.nid, votedMinarNID);
  if (!result.success) return res.status(400).json({ message: result.message });

  res.json({ message: result.message });
});

function hasVotingEnded() {
  const votingPeriod = JSON.parse(
    fs.readFileSync("votingPeriod.json", "utf-8")
  );
  const now = new Date();
  return now > new Date(votingPeriod.endDate);
}

// Admin triggers tally
app.get("/tally-votes", authenticateJWT, authorizeRole("admin"), (req, res) => {
  if (!hasVotingEnded()) {
    return res.status(400).json({ message: "Voting period is still ongoing" });
  }

  const results = tallyVotes();
  res.json({ electedMinars: results });
});

function writeZoneMinars(data) {
  fs.writeFileSync("zoneMinars.json", JSON.stringify(data, null, 2));
}
function tallyVotesAutomatically() {
  const results = tallyVotes();
  writeZoneMinars(results);
  console.log(
    "✅ [AUTO-TALLY] Votes tallied automatically at:",
    new Date().toISOString()
  );
  console.log("🗳️ Elected Minars:", results);
}

function scheduleAutomaticTally() {
  const votingPeriod = JSON.parse(
    fs.readFileSync("votingPeriod.json", "utf-8")
  );
  const now = new Date();
  const endDate = new Date(votingPeriod.endDate || votingPeriod.end);

  const delay = endDate - now;

  if (delay > 0) {
    console.log(
      `⏳ Scheduling auto-tally in ${Math.round(delay / 1000)} seconds`
    );
    setTimeout(() => {
      tallyVotesAutomatically();
    }, delay);
  } else {
    console.log(
      "⚠️ Voting period already ended or invalid. Not scheduling auto-tally."
    );
  }
}

app.post(
  "/tally-votes",
  authenticateJWT,
  authorizeRole("admin"),
  (req, res) => {
    try {
      const users = readUsers();
      const votes = readVotes();

      const zones = {};
      for (const vote of votes) {
        const voter = users.find((u) => u.nid === vote.voterNID);
        const minar = users.find((u) => u.nid === vote.minarNID);
        if (!voter || !minar || voter.zone !== minar.zone) continue;

        const weight = voter.wallet || 0;
        if (!zones[minar.zone]) zones[minar.zone] = {};
        if (!zones[minar.zone][minar.nid]) zones[minar.zone][minar.nid] = 0;

        zones[minar.zone][minar.nid] += weight;
      }

      const result = {};
      for (const zone in zones) {
        const scores = zones[zone];
        const winner = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];
        result[zone] = winner ? winner[0] : null;
      }

      writeZoneMinars(result);
      res.json({ message: "Votes tallied", electedMinars: result });
    } catch (err) {
      console.error("Tally error:", err);
      res.status(500).json({ message: "Failed to tally votes" });
    }
  }
);
app.post(
  "/set-voting-period",
  authenticateJWT,
  authorizeRole("admin"),
  (req, res) => {
    const { start, end } = req.body;

    if (!start || !end) {
      return res
        .status(400)
        .json({ message: "Start and end times are required." });
    }

    try {
      fs.writeFileSync(
        "votingPeriod.json",
        JSON.stringify({ start, end }, null, 2)
      );

      scheduleAutomaticTally(); // ✅ Reschedule on update

      res.json({ message: "✅ Voting period set successfully.", start, end });
    } catch (err) {
      console.error("Failed to set voting period:", err);
      res.status(500).json({ message: "Error saving voting period." });
    }
  }
);

`-// --- Start Server ---`;
server.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});
