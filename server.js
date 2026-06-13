require('dotenv').config();
const express = require('express');
const { google } = require('googleapis');
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { createClient } = require('@supabase/supabase-js');
const multer = require('multer');
const cron = require('node-cron');

const app = express();
app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const upload = multer({ storage: multer.memoryStorage() });

const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const COOKIE_NAME = 'yt_session';

// ─── Supabase ──────────────────────────────────────────────────────────────
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);

// ─── JWT Session Helpers ───────────────────────────────────────────────────
function setSession(res, payload) {
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  res.cookie(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
  });
}

function getSession(req) {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    if (!token) return null;
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function clearSession(res) {
  res.clearCookie(COOKIE_NAME);
}

// ─── OAuth2 Helpers ────────────────────────────────────────────────────────
function getOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI || `http://localhost:${process.env.PORT || 3000}/auth/callback`
  );
}

function getAuthedClient(tokens) {
  const oauth2Client = getOAuth2Client();
  oauth2Client.setCredentials(tokens);
  return oauth2Client;
}

// ─── Auth Routes ───────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const oauth2Client = getOAuth2Client();
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: [
      'https://www.googleapis.com/auth/youtube.readonly',
      'https://www.googleapis.com/auth/youtube.upload',
      'https://www.googleapis.com/auth/youtube.force-ssl',
      'https://www.googleapis.com/auth/userinfo.email',
    ],
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

    if (dbErr) {
      console.error('DB upsert error:', dbErr.message);
      return res.redirect('/?auth_error=db_error');
    }

    setSession(res, { userId: user.id, email, tokens });
    res.redirect('/?auth=success');
  } catch (err) {
    console.error('Token exchange error:', err.message);
    res.redirect('/?auth_error=token_exchange_failed');
  }
});

app.get('/auth/logout', (req, res) => {
  clearSession(res);
  res.redirect('/');
});

app.get('/auth/status', (req, res) => {
  const session = getSession(req);
  res.json({ authenticated: !!session, email: session?.email || null });
});

// ─── API: Search ───────────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing query' });

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(session.tokens) });
    const response = await youtube.search.list({
      part: ['snippet'], q, type: ['video'], maxResults: 5, order: 'relevance',
    });

    const videos = response.data.items.map(item => ({
      videoId: item.id.videoId,
      title: item.snippet.title,
      channelTitle: item.snippet.channelTitle,
      thumbnail: item.snippet.thumbnails?.medium?.url,
      publishedAt: item.snippet.publishedAt,
    }));

    if (session.userId) {
      await supabase.from('search_history').insert({
        user_id: session.userId, query: q, results_count: videos.length,
      });
    }

    res.json({ videos });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Video Metadata ───────────────────────────────────────────────────
app.get('/api/video/:videoId', async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });
  const { videoId } = req.params;

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(session.tokens) });
    const response = await youtube.videos.list({
      part: ['snippet', 'statistics', 'contentDetails'], id: [videoId],
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

    if (session.userId) {
      await supabase.from('saved_metadata').upsert({
        user_id: session.userId,
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

// ─── API: Upload (with scheduling and made-for-kids) ──────────────────────
app.post('/api/upload', upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 },
]), async (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Not authenticated' });

  const videoFile = req.files?.video?.[0];
  if (!videoFile) return res.status(400).json({ error: 'No video file provided' });

  const { title, description, tags, categoryId, privacyStatus, madeForKids, publishAt } = req.body;

  // SSE setup
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  const sendProgress = (() => {
    let lastPct = -1;
    return (uploaded, total) => {
      const pct = Math.min(99, Math.round((uploaded / total) * 100));
      if (pct !== lastPct) {
        lastPct = pct;
        send({ stage: 'uploading', progress: pct, message: `Uploading… ${pct}%` });
      }
    };
  })();

  try {
    const accessToken = session.tokens.access_token;
    const fileSize = videoFile.size;
    const mimeType = videoFile.mimetype || 'video/mp4';
    const tagsArr = tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [];
    const isScheduled = publishAt ? true : false;
    const pubStatus = isScheduled ? 'scheduled' : (privacyStatus || 'private');

    send({ stage: 'uploading', progress: 0, message: 'Initialising upload…' });

    // Build upload request
    const uploadBody = {
      snippet: {
        title: title || 'My Video',
        description: description || '',
        tags: tagsArr,
        categoryId: categoryId || '22',
      },
      status: { privacyStatus: pubStatus },
      processingDetails: {},
      selfDeclaredMadeForKids: madeForKids === 'true' || madeForKids === true,
    };

    const initResp = await axios.post(
      'https://www.googleapis.com/upload/youtube/v3/videos?uploadType=resumable&part=snippet,status,processingDetails',
      uploadBody,
      {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'X-Upload-Content-Type': mimeType,
          'X-Upload-Content-Length': fileSize,
        },
      }
    );

    const uploadUri = initResp.headers.location;
    if (!uploadUri) throw new Error('YouTube did not return an upload URI');

    // Chunked upload
    const CHUNK = 8 * 1024 * 1024;
    const buffer = videoFile.buffer;
    let offset = 0;
    let youtubeVideoId = null;

    while (offset < fileSize) {
      const end = Math.min(offset + CHUNK, fileSize);
      const chunk = buffer.slice(offset, end);

      const chunkResp = await axios.put(uploadUri, chunk, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': mimeType,
          'Content-Range': `bytes ${offset}-${end - 1}/${fileSize}`,
          'Content-Length': chunk.length,
        },
        validateStatus: s => s === 200 || s === 201 || s === 308,
        maxBodyLength: Infinity,
        maxContentLength: Infinity,
      });

      offset = end;
      sendProgress(offset, fileSize);

      if (chunkResp.status === 200 || chunkResp.status === 201) {
        youtubeVideoId = chunkResp.data?.id;
        break;
      }
    }

    if (!youtubeVideoId) throw new Error('Upload completed but no video ID returned');

    send({ stage: 'uploaded', progress: 100, message: 'Video uploaded! Processing metadata…' });

    // Thumbnail
    const thumbFile = req.files?.thumbnail?.[0];
    if (thumbFile) {
      try {
        send({ stage: 'thumbnail', message: 'Setting thumbnail…' });
        await axios.post(
          `https://www.googleapis.com/upload/youtube/v3/thumbnails/set?videoId=${encodeURIComponent(youtubeVideoId)}&uploadType=media`,
          thumbFile.buffer,
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              'Content-Type': thumbFile.mimetype || 'image/jpeg',
              'Content-Length': thumbFile.size,
            },
            maxBodyLength: Infinity,
          }
        );
      } catch (thumbErr) {
        send({ stage: 'thumbnail_warn', message: 'Thumbnail upload failed (video still uploaded).' });
        console.warn('Thumbnail error:', thumbErr.response?.data || thumbErr.message);
      }
    }

    // Schedule if needed
    let scheduledTime = null;
    if (isScheduled && publishAt) {
      scheduledTime = new Date(publishAt).toISOString();
      // Store scheduled job (set status to scheduled)
      const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(session.tokens) });
      try {
        await youtube.videos.update({
          part: ['status'],
          requestBody: {
            id: youtubeVideoId,
            status: {
              privacyStatus: privacyStatus || 'private',
              publishAt: scheduledTime,
            },
          },
        });
        send({ stage: 'uploaded', message: 'Video scheduled for publishing!' });
      } catch (schedErr) {
        console.warn('Schedule error:', schedErr.message);
      }
    }

    // Log to Supabase
    if (session.userId) {
      const { error: dbErr } = await supabase.from('upload_history').insert({
        user_id: session.userId,
        title,
        description,
        tags: tagsArr,
        category_id: categoryId,
        privacy_status: privacyStatus || 'private',
        youtube_video_id: youtubeVideoId,
        upload_status: 'success',
        youtube_url: `https://www.youtube.com/watch?v=${youtubeVideoId}`,
        made_for_kids: madeForKids === 'true' || madeForKids === true,
        scheduled_at: scheduledTime,
      });
      if (dbErr) console.warn('DB log error:', dbErr.message);
    }

    send({
      stage: 'done',
      videoId: youtubeVideoId,
      url: `https://www.youtube.com/watch?v=${youtubeVideoId}`,
      studioUrl: `https://studio.youtube.com/video/${youtubeVideoId}/edit`,
    });

    res.end();
  } catch (err) {
    const msg = err.response?.data?.error?.message || err.message;
    console.error('Upload error:', msg);
    send({ stage: 'error', message: msg });
    res.end();
  }
});

// ─── API: History ──────────────────────────────────────────────────────────
app.get('/api/history/searches', async (req, res) => {
  const session = getSession(req);
  if (!session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase.from('search_history').select('*')
    .eq('user_id', session.userId).order('searched_at', { ascending: false }).limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ searches: data });
});

app.get('/api/history/uploads', async (req, res) => {
  const session = getSession(req);
  if (!session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase.from('upload_history').select('*')
    .eq('user_id', session.userId).order('uploaded_at', { ascending: false }).limit(50);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ uploads: data });
});

app.get('/api/history/saved', async (req, res) => {
  const session = getSession(req);
  if (!session?.userId) return res.status(401).json({ error: 'Not authenticated' });
  const { data, error } = await supabase.from('saved_metadata').select('*')
    .eq('user_id', session.userId).order('saved_at', { ascending: false }).limit(20);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ saved: data });
});

// ─── Scheduled Upload Processing ──────────────────────────────────────────
// Run every minute to check for scheduled uploads
cron.schedule('* * * * *', async () => {
  try {
    const now = new Date();
    const { data: scheduled, error } = await supabase
      .from('upload_history')
      .select('*')
      .eq('upload_status', 'success')
      .lte('scheduled_at', now.toISOString())
      .is('published_at', null)
      .limit(10);

    if (error) {
      console.error('Schedule check error:', error.message);
      return;
    }

    for (const upload of scheduled || []) {
      try {
        const { data: user } = await supabase.from('users').select('*').eq('id', upload.user_id).single();
        if (!user) continue;

        const oauth2Client = getAuthedClient(user.tokens);
        const youtube = google.youtube({ version: 'v3', auth: oauth2Client });

        // Update privacy status from scheduled to public
        await youtube.videos.update({
          part: ['status'],
          requestBody: {
            id: upload.youtube_video_id,
            status: {
              privacyStatus: upload.privacy_status === 'scheduled' ? 'public' : upload.privacy_status,
            },
          },
        });

        // Mark as published
        await supabase.from('upload_history').update({
          published_at: now.toISOString(),
        }).eq('id', upload.id);

        console.log(`Published scheduled video: ${upload.youtube_video_id}`);
      } catch (err) {
        console.error(`Error publishing ${upload.youtube_video_id}:`, err.message);
      }
    }
  } catch (err) {
    console.error('Cron job error:', err.message);
  }
});

// ─── Start ─────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));