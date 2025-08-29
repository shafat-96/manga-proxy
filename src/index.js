const express = require('express');
const { fetchMangaParkImage } = require('./providers/mangapark');
const { fetchMangakakalotImage } = require('./providers/mangakakalot');
const { fetchMangabuddyImage } = require('./providers/mangabuddy');
const { ipv6ProxyHandler } = require('./ipv6Proxy');

const app = express();
const PORT = process.env.PORT || 3000;

// Generic CORS middleware
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  next();
});

/**
 * ANY /i6?url=<TARGET_URL>[&headers=<JSON>]
 * General-purpose proxy with optional IPv6 rotation and API token auth.
 */
app.all('/i6', ipv6ProxyHandler);

/**
 * GET /mangapark?url=<IMAGE_URL>
 * Proxies an image from MangaPark with the correct headers.
 */
app.get('/mangapark', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).send('No URL provided');
  }

  try {
    const imageBuffer = await fetchMangaParkImage(url);
    res.setHeader('Content-Type', 'image/jpeg');
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch image');
  }
});

/**
 * GET /mangakakalot?url=<IMAGE_URL>
 * Proxies an image from MangaKakalot with the correct headers.
 */
app.get('/mangakakalot', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).send('No URL provided');
  }

  try {
    const imageBuffer = await fetchMangakakalotImage(url);
    res.setHeader('Content-Type', 'image/jpeg');
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch image');
  }
});

/**
 * GET /mangabuddy?url=<IMAGE_URL>
 * Proxies an image from MangaBuddy with the correct headers.
 */
app.get('/mangabuddy', async (req, res) => {
  const { url } = req.query;

  if (!url) {
    return res.status(400).send('No URL provided');
  }

  try {
    const imageBuffer = await fetchMangabuddyImage(url);
    res.setHeader('Content-Type', 'image/jpeg');
    res.send(imageBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to fetch image');
  }
});

app.listen(PORT, () => {
  console.log(`MangaPark proxy running at http://localhost:${PORT}`);
});
