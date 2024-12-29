const express = require("express");
const axios = require("axios");
const path = require("path");

const app = express();
const PORT = 3000;

// Initial Config
let websiteUrl = "https://fine-sunny-weeder.glitch.me/"; // Default website
let intervalInSeconds = 180; // Default interval (60 seconds)
let websiteStatus = "unknown"; // Can be "green", "yellow", or "red"

// Serve Static Files
app.use(express.static(path.join(__dirname, "public")));
app.use(express.json());

// Endpoint to Get Current Config and Status
app.get("/config", (req, res) => {
  res.json({ websiteUrl, intervalInSeconds, websiteStatus });
});

// Endpoint to Update Config
app.post("/config", (req, res) => {
  const { url, interval } = req.body;
  if (url) websiteUrl = url;
  if (interval) intervalInSeconds = parseInt(interval);
  res.json({ message: "Config updated successfully!" });
});

// Ping Website
const pingWebsite = async () => {
  if (!websiteUrl) return;
  try {
    const response = await axios.get(websiteUrl, { timeout: 5000 });
    websiteStatus = response.status === 200 ? "green" : "yellow";
    console.log(`Ping successful: ${websiteUrl} - Status: ${response.status}`);
  } catch (error) {
    websiteStatus = "red";
    console.log(`Ping failed: ${websiteUrl} - Error: ${error.message}`);
  }
};

// Schedule Pings
setInterval(pingWebsite, intervalInSeconds * 1000);

// Start Server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
