require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { google } = require('googleapis');
const path = require('path');
const axios = require('axios');

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'yt-metadata-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 }
}));

function getOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI || `http://localhost:${process.env.PORT || 3000}/auth/callback`
  );
}

function getAuthedClient(req) {
  const oauth2Client = getOAuth2Client();
  oauth2Client.setCredentials(req.session.tokens);
  oauth2Client.on('tokens', (tokens) => {
    req.session.tokens = { ...req.session.tokens, ...tokens };
  });
  return oauth2Client;
}

// Auth routes
app.get('/auth/login', (req, res) => {
  const oauth2Client = getOAuth2Client();
  const scopes = [
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/youtube.upload',
    'https://www.googleapis.com/auth/youtube.force-ssl',
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent',
  });
  res.redirect(url);
});

app.get('/api/auth/login', (req, res) => res.redirect('/auth/login'));

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect('/?auth_error=' + encodeURIComponent(error));
  try {
    const oauth2Client = getOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    req.session.tokens = tokens;
    res.redirect('/?auth=success');
  } catch (err) {
    console.error('Token exchange error:', err.message);
    res.redirect('/?auth_error=token_exchange_failed');
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.tokens });
});

// Search
app.get('/api/search', async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing query' });
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(req) });
    const response = await youtube.search.list({
      part: ['snippet'],
      q,
      type: ['video'],
      maxResults: 5,
      order: 'relevance',
    });

    const videos = response.data.items.map(item => ({
      videoId: item.id.videoId,
      title: item.snippet.title,
      channelTitle: item.snippet.channelTitle,
      thumbnail: item.snippet.thumbnails?.medium?.url,
      publishedAt: item.snippet.publishedAt,
    }));

    res.json({ videos });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Video metadata
app.get('/api/video/:videoId', async (req, res) => {
  const { videoId } = req.params;
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(req) });
    const response = await youtube.videos.list({
      part: ['snippet', 'statistics', 'contentDetails'],
      id: [videoId],
    });

    if (!response.data.items?.length) return res.status(404).json({ error: 'Video not found' });

    const video = response.data.items[0];
    const snippet = video.snippet;

    res.json({
      videoId,
      title: snippet.title,
      description: snippet.description,
      tags: snippet.tags || [],
      channelTitle: snippet.channelTitle,
      publishedAt: snippet.publishedAt,
      thumbnail: snippet.thumbnails?.maxres?.url || snippet.thumbnails?.high?.url,
      statistics: video.statistics,
      categoryId: snippet.categoryId,
    });
  } catch (err) {
    console.error('Video fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Init resumable upload — returns YouTube upload URI
app.post('/api/upload/init', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  const { title, description, tags, categoryId, privacyStatus, fileSize, mimeType } = req.body;

  try {
    const accessToken = req.session.tokens.access_token;

    const initResponse = await axios.post(
      'https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status',
      {
        snippet: {
          title: title || 'My Video',
          description: description || '',
          tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
          categoryId: categoryId || '22',
        },
        status: {
          privacyStatus: privacyStatus || 'private',
        },
      },
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'X-Upload-Content-Type': mimeType || 'video/mp4',
          'X-Upload-Content-Length': fileSize,
        },
      }
    );

    const uploadUri = initResponse.headers.location;
    if (!uploadUri) throw new Error('YouTube did not return an upload URI');

    res.json({ uploadUri });
  } catch (err) {
    console.error('Upload init error:', err.response?.data || err.message);
    const msg = err.response?.data?.error?.message || err.message;
    res.status(500).json({ error: msg });
  }
});

// Thumbnail upload
app.post('/api/upload/thumbnail', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  const { videoId, dataUrl, mimeType } = req.body;
  if (!videoId || !dataUrl) return res.status(400).json({ error: 'Missing videoId or dataUrl' });

  try {
    const accessToken = req.session.tokens.access_token;
    const base64Data = dataUrl.replace(/^data:[^;]+;base64,/, '');
    const buffer = Buffer.from(base64Data, 'base64');

    await axios.post(
      `https://www.googleapis.com/upload/youtube/v3/thumbnails/set?videoId=${encodeURIComponent(videoId)}&uploadType=media`,
      buffer,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': mimeType || 'image/jpeg',
          'Content-Length': buffer.length,
        },
        maxBodyLength: Infinity,
      }
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('Thumbnail error:', err.response?.data || err.message);
    const msg = err.response?.data?.error?.message || err.message;
    res.status(500).json({ error: msg });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});