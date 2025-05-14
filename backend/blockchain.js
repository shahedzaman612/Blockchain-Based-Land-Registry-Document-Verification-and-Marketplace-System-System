const fs = require("fs");
const crypto = require("crypto");
const path = require("path");

const blockchainFile = path.join(__dirname, "blockchain.json");

// Load blockchain or start new
let blockchain = [];
try {
  if (fs.existsSync(blockchainFile)) {
    const data = fs.readFileSync(blockchainFile);
    blockchain = JSON.parse(data);
  }
} catch (err) {
  console.error("Error reading blockchain file:", err);
  blockchain = [];
}

// Hashing function (string or buffer)
function calculateHash(data) {
  return crypto.createHash("sha256").update(data).digest("hex");
}

// Document hashing (image/pdf)
function hashDocument(filePath) {
  const buffer = fs.readFileSync(filePath);
  return calculateHash(buffer);
}

// Create new block (and optionally save)
function createBlock({
  transactionId,
  from,
  fromNID,
  to,
  toNID,
  docs,
  nonce,
  autoSave = true,
}) {
  const previousBlock = blockchain[blockchain.length - 1];
  const previousHash = previousBlock ? previousBlock.hash : "0";
  const timestamp = new Date().toISOString();

  const dcrHash = hashDocument(docs.dcr);
  const porchaHash = hashDocument(docs.porcha);
  const dolilHash = hashDocument(docs.dolil);

  const blockPayload = {
    transactionId,
    from,
    fromNID,
    to,
    toNID,
    dcrHash,
    porchaHash,
    dolilHash,
    nonce,
    previousHash,
    timestamp,
  };

  const blockString = JSON.stringify(
    blockPayload,
    Object.keys(blockPayload).sort()
  );
  const hash = calculateHash(blockString);

  const block = {
    blockNumber: blockchain.length + 1,
    ...blockPayload,
    hash,
  };

  if (autoSave) saveBlock(block);
  return block;
}

// Save block to chain
function saveBlock(block) {
  blockchain.push(block);
  fs.writeFileSync(blockchainFile, JSON.stringify(blockchain, null, 2));
}

// Verify document by hash and doc type
function verifyDocument(fileHash, docType) {
  const key = docType.toLowerCase() + "Hash"; // e.g., "dolilHash", "porchaHash", "dcrHash"
  for (const block of blockchain) {
    if (block[key] === fileHash) {
      return block;
    }
  }
  return null;
}

module.exports = {
  blockchain,
  createBlock,
  saveBlock,
  hashDocument,
  calculateHash,
  verifyDocument,
};
