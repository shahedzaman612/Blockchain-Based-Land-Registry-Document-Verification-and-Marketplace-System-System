const fs = require("fs");
const path = require("path");

const votesFile = path.join(__dirname, "votes.json");
const usersFile = path.join(__dirname, "users.json");

function readVotes() {
  return JSON.parse(fs.readFileSync(votesFile, "utf-8"));
}

function writeVotes(votes) {
  fs.writeFileSync(votesFile, JSON.stringify(votes, null, 2));
}

function readUsers() {
  return JSON.parse(fs.readFileSync(usersFile, "utf-8"));
}

// Save a vote (1 vote per user per zone)
function castVote(voterNID, votedMinarNID) {
  const users = readUsers();
  const voter = users.find((u) => u.nid === voterNID);
  const minar = users.find((u) => u.nid === votedMinarNID);

  if (!voter || !minar || voter.zone !== minar.zone) {
    return { success: false, message: "Invalid vote or mismatched zone" };
  }

  const votes = readVotes();
  const existing = votes.find(
    (v) => v.voterNID === voterNID && v.zone === voter.zone
  );
  if (existing)
    return { success: false, message: "You already voted in this zone." };

  votes.push({
    voterNID,
    votedMinarNID,
    zone: voter.zone,
    weight: voter.wallet || 1,
    timestamp: new Date().toISOString(),
  });

  writeVotes(votes);
  return { success: true, message: "Vote cast successfully." };
}

// Tally votes and return elected Minar per zone
function tallyVotes() {
  const votes = readVotes();
  const zoneMap = {};

  for (const vote of votes) {
    if (!zoneMap[vote.zone]) zoneMap[vote.zone] = {};
    if (!zoneMap[vote.zone][vote.votedMinarNID])
      zoneMap[vote.zone][vote.votedMinarNID] = 0;
    zoneMap[vote.zone][vote.votedMinarNID] += vote.weight;
  }

  const elected = {};
  for (const zone in zoneMap) {
    const sorted = Object.entries(zoneMap[zone]).sort((a, b) => b[1] - a[1]);
    if (sorted.length > 0) {
      elected[zone] = sorted[0][0]; // Top voted Minar
    }
  }

  return elected;
}

module.exports = { castVote, tallyVotes, readVotes, writeVotes };
