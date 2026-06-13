require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { google } = require('googleapis');
const path = require('path');
const axios = require('axios');
const { createClient } = require('@supabase/supabase-js');

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

// ─── Supabase Client ───────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ─── OAuth2 Helpers ────────────────────────────────────────────────────────
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
  oauth2Client.on('tokens', async (tokens) => {
    req.session.tokens = { ...req.session.tokens, ...tokens };
    if (req.session.userId) {
      await supabase.from('users').update({
        access_token: tokens.access_token || req.session.tokens.access_token,
        refresh_token: tokens.refresh_token || req.session.tokens.refresh_token,
        token_expiry: tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : null,
      }).eq('id', req.session.userId);
    }
  });
  return oauth2Client;
}

// ─── Auth Routes ───────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const oauth2Client = getOAuth2Client();
  const scopes = [
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/youtube.upload',
    'https://www.googleapis.com/auth/youtube.force-ssl',
    'https://www.googleapis.com/auth/userinfo.email',
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

    oauth2Client.setCredentials(tokens);
    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    const userInfo = await oauth2.userinfo.get();
    const email = userInfo.data.email;

    let channelId = null, channelTitle = null;
    try {
      const yt = google.youtube({ version: 'v3', auth: oauth2Client });
      const ch = await yt.channels.list({ part: ['snippet'], mine: true });
      if (ch.data.items?.length) {
        channelId = ch.data.items[0].id;
        channelTitle = ch.data.items[0].snippet.title;
      }
    } catch (_) {}

    const { data: user, error: dbErr } = await supabase
      .from('users')
      .upsert({
        google_email: email,
        google_channel_id: channelId,
        google_channel_title: channelTitle,
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token || null,
        token_expiry: tokens.expiry_date ? new Date(tokens.expiry_date).toISOString() : null,
      }, { onConflict: 'google_email' })
      .select()
      .single();

    if (dbErr) console.error('DB upsert error:', dbErr.message);
    else req.session.userId = user.id;

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

// ─── API: Search Videos ────────────────────────────────────────────────────
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

    if (req.session.userId) {
      await supabase.from('search_history').insert({
        user_id: req.session.userId,
        query: q,
        results_count: videos.length,
      });
    }

    res.json({ videos });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Get Video Metadata ───────────────────────────────────────────────
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
    const stats = video.statistics;

    const metadata = {
      videoId,
      title: snippet.title,
      description: snippet.description,
      tags: snippet.tags || [],
      channelTitle: snippet.channelTitle,
      publishedAt: snippet.publishedAt,
      thumbnail: snippet.thumbnails?.maxres?.url || snippet.thumbnails?.high?.url,
      statistics: stats,
      categoryId: snippet.categoryId,
    };

    if (req.session.userId) {
      await supabase.from('saved_metadata').upsert({
        user_id: req.session.userId,
        video_id: videoId,
        title: snippet.title,
        description: snippet.description,
        tags: snippet.tags || [],
        category_id: snippet.categoryId,
        channel_title: snippet.channelTitle,
        thumbnail_url: metadata.thumbnail,
        view_count: parseInt(stats?.viewCount) || 0,
        like_count: parseInt(stats?.likeCount) || 0,
        comment_count: parseInt(stats?.commentCount) || 0,
        published_at: snippet.publishedAt,
      }, { onConflict: 'user_id,video_id' });
    }

    res.json(metadata);
  } catch (err) {
    console.error('Video fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Init Resumable Upload ────────────────────────────────────────────
app.post('/api/upload/init', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  const { title, description, tags, categoryId, privacyStatus, fileSize, mimeType, sourceVideoId } = req.body;

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
        status: { privacyStatus: privacyStatus || 'private' },
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

    let uploadRecordId = null;
    if (req.session.userId) {
      const { data } = await supabase.from('upload_history').insert({
        user_id: req.session.userId,
        title,
        description,
        tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
        category_id: categoryId,
        privacy_status: privacyStatus || 'private',
        source_video_id: sourceVideoId || null,
        upload_status: 'pending',
      }).select().single();
      uploadRecordId = data?.id;
    }

    res.json({ uploadUri, uploadRecordId });
  } catch (err) {
    console.error('Upload init error:', err.response?.data || err.message);
    res.status(500).json({ error: err.response?.data?.error?.message || err.message });
  }
});

// ─── API: Confirm Upload ───────────────────────────────────────────────────
app.post('/api/upload/confirm', async (req, res) => {
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });
  const { uploadRecordId, youtubeVideoId, success, errorMessage } = req.body;
  try {
    if (uploadRecordId && req.session.userId) {
      await supabase.from('upload_history').update({
        youtube_video_id: youtubeVideoId || null,
        upload_status: success ? 'success' : 'failed',
        error_message: errorMessage || null,
        youtube_url: youtubeVideoId ? `https://www.youtube.com/watch?v=${youtubeVideoId}` : null,
      }).eq('id', uploadRecordId).eq('user_id', req.session.userId);
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Thumbnail Upload ─────────────────────────────────────────────────
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
    res.status(500).json({ error: err.response?.data?.error?.message || err.message });
  }
});

// ─── API: History Endpoints ────────────────────────────────────────────────
app.get('/api/history/searches', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase
    .from('search_history').select('*')
    .eq('user_id', req.session.userId)
    .order('searched_at', { ascending: false }).limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ searches: data });
});

app.get('/api/history/saved', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase
    .from('saved_metadata').select('*')
    .eq('user_id', req.session.userId)
    .order('saved_at', { ascending: false }).limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ saved: data });
});

app.get('/api/history/uploads', async (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase
    .from('upload_history').select('*')
    .eq('user_id', req.session.userId)
    .order('uploaded_at', { ascending: false }).limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ uploads: data });
});

// ─── Start ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));