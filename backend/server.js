const express = require("express");
const multer = require("multer");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const router = express.Router();

const { createBlock, verifyDocument, hashDocument } = require("./blockchain");

const app = express();
const PORT = 3000;
const SECRET_KEY = "your_secret_key"; // Replace this with an actual secret key in production

// Middleware
app.use(cors({ origin: "*" }));
app.use(express.json()); // Parse JSON request bodies
app.use("/uploads", express.static(path.join(__dirname, "uploads"))); // Serve uploaded images from the 'uploads' folder
app.use(express.static(path.join(__dirname, "public"))); // Serve static files from 'public'

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

    res.json({ token });
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
      imagePath: `/uploads/${path.basename(imagePath)}`, // Serve the image path from the 'uploads' folder
      postedBy: req.user.username,
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

// Handle Buy Request Route
// Handle Buy Request Route
app.post("/buy-request/:adId", authenticateJWT, (req, res) => {
  try {
    const adId = req.params.adId;
    const buyerUsername = req.user.username; // Get the username of the buyer
    const ads = readAds();
    const ad = ads.find((ad) => ad.id == adId);

    if (!ad) {
      return res.status(404).json({ message: "Ad not found" });
    }

    // Create the message
    const message = {
      buyer: buyerUsername,
      message: `A buyer is interested in your land ad: "${ad.title}". Contact them for more details.`,
      adId: ad.id,
      timestamp: new Date().toISOString(),
    };

    // Store the message (you can change this to save in a database or a file)
    const messagesFile = path.join(__dirname, "messages.json");
    const messages = fs.existsSync(messagesFile)
      ? JSON.parse(fs.readFileSync(messagesFile))
      : [];

    // Add the new message to the list of messages for the ad poster
    messages.push({ to: ad.postedBy, ...message });

    // Save the messages back to the file
    fs.writeFileSync(messagesFile, JSON.stringify(messages, null, 2));

    res.json({ message: "Buy request sent successfully!", adId: ad.id });
  } catch (err) {
    console.error("Error handling buy request:", err);
    res.status(500).json({ message: "Failed to process buy request" });
  }
});
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

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
