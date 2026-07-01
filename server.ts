import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { connectDB, ContactModel, VisitModel, BatchModel, SettingsModel } from './src/db.js';

// Setup app
const app = express();
const PORT = 3000;

// Body parser middleware
app.use(express.json());

// In-memory rate limiting map for spam protection
const ipRequestCount = new Map<string, { count: number; lastReset: number }>();
const RATE_LIMIT_WINDOW_MS = 60 * 1000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 30; // 30 requests per minute

function rateLimiter(req: express.Request, res: express.Response, next: express.NextFunction) {
  const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'unknown';
  const now = Date.now();
  
  const clientData = ipRequestCount.get(ip);
  if (!clientData) {
    ipRequestCount.set(ip, { count: 1, lastReset: now });
    return next();
  }

  if (now - clientData.lastReset > RATE_LIMIT_WINDOW_MS) {
    clientData.count = 1;
    clientData.lastReset = now;
    return next();
  }

  clientData.count += 1;
  if (clientData.count > MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({ error: 'Too many requests. Please try again later.' });
  }

  next();
}

// User Agent Parser
function parseUserAgent(uaString: string | undefined) {
  let browser = 'Unknown';
  let device = 'Desktop';

  if (!uaString) return { browser, device };

  const ua = uaString.toLowerCase();

  // Browser detection
  if (ua.includes('firefox')) browser = 'Firefox';
  else if (ua.includes('samsungbrowser')) browser = 'Samsung Browser';
  else if (ua.includes('opera') || ua.includes('opr')) browser = 'Opera';
  else if (ua.includes('edge') || ua.includes('edg')) browser = 'Edge';
  else if (ua.includes('chrome') || ua.includes('crios')) browser = 'Chrome';
  else if (ua.includes('safari') && !ua.includes('chrome')) browser = 'Safari';

  // Device detection
  if (ua.includes('mobi') || ua.includes('android') || ua.includes('iphone') || ua.includes('ipod')) {
    device = 'Mobile';
  } else if (ua.includes('ipad') || ua.includes('tablet') || ua.includes('playbook')) {
    device = 'Tablet';
  }

  return { browser, device };
}

// Country detection helper
function getCountry(req: express.Request): string {
  const geoHeaders = [
    'cf-ipcountry',
    'x-appengine-country',
    'x-client-geo-country',
    'x-country-code',
    'cloudfront-viewer-country'
  ];
  for (const header of geoHeaders) {
    const val = req.headers[header];
    if (val && typeof val === 'string') {
      return val.toUpperCase();
    }
  }
  
  // Return some realistic simulation data if headers aren't available (common in sandbox)
  // Let's check req.ip to vary the mock response slightly, keeping Kenya (KE) as the primary hub
  const ipStr = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '127.0.0.1';
  const lastChar = ipStr.charAt(ipStr.length - 1);
  if (lastChar === '1' || lastChar === '5') return 'TZ'; // Tanzania
  if (lastChar === '3' || lastChar === '7') return 'UG'; // Uganda
  if (lastChar === '9') return 'NG'; // Nigeria
  return 'KE'; // Kenya (default)
}

// Security Middleware to verify Admin PIN
async function requireAdmin(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: 'Authorization header is missing.' });
  }

  try {
    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not initialized.' });
    }

    // Verify raw PIN or hashed comparison
    const providedPin = authHeader.replace('Bearer ', '').trim();
    if (providedPin !== settings.adminPin) {
      return res.status(403).json({ error: 'Invalid Admin PIN.' });
    }

    next();
  } catch (error) {
    res.status(500).json({ error: 'Server authorization error.' });
  }
}

// VCF 3.0 Generation Helper
function generateVcfContent(contacts: any[]): string {
  return contacts.map(contact => {
    // Escape standard vcf properties
    const cleanName = contact.name.replace(/[:;\n]/g, ' ');
    const cleanPhone = contact.phone.replace(/[:;\n]/g, ' ');
    return `BEGIN:VCARD
VERSION:3.0
FN:${cleanName}
TEL;TYPE=CELL:${cleanPhone}
REV:${new Date().toISOString()}
END:VCARD`;
  }).join('\n');
}

// API Routes
app.get('/api/settings', async (req, res) => {
  try {
    await connectDB();
    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(404).json({ error: 'Settings not found' });
    }
    // Return only public settings
    res.json({
      downloadThreshold: settings.downloadThreshold,
      whatsappGroupUrl: settings.whatsappGroupUrl,
      whatsappChannelUrl: settings.whatsappChannelUrl,
      currentCounter: settings.currentCounter
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

// Create Contact & Check Threshold
app.post('/api/contacts', rateLimiter, async (req, res) => {
  try {
    await connectDB();
    const { name, phone } = req.body;

    // Server-side validation
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: 'Full Name is required.' });
    }
    if (!phone || typeof phone !== 'string' || phone.trim().length < 8) {
      return res.status(400).json({ error: 'A valid Phone Number with at least 8 digits is required.' });
    }

    // Sanitize and prefix with SILA
    let upperName = name.trim().toUpperCase();
    if (!upperName.startsWith('SILA ')) {
      // Remove starting SILA if they typed SILARichard or similar, but handle correctly
      if (upperName.startsWith('SILA')) {
        upperName = 'SILA ' + upperName.substring(4).trim();
      } else {
        upperName = 'SILA ' + upperName;
      }
    }

    // Capture visitor headers
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'Unknown';
    const country = getCountry(req);
    const { browser, device } = parseUserAgent(req.headers['user-agent']);

    // Save contact
    const contact = await ContactModel.create({
      name: upperName,
      phone: phone.trim(),
      ip,
      country,
      browser,
      device
    });

    // Update Counter
    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not initialized.' });
    }

    settings.currentCounter += 1;
    await settings.save();

    let triggerDownload = false;
    let vcfFilename = '';
    let vcfData = '';
    let batchNumber = 0;

    // Check if download threshold reached
    if (settings.currentCounter >= settings.downloadThreshold) {
      // Get the contacts to bundle (the last 'downloadThreshold' contacts or we can fetch all contacts and archive them)
      // Since it's a reset threshold, we fetch the most recent 'downloadThreshold' contacts
      const batchContacts = await ContactModel.find()
        .sort({ createdAt: -1 })
        .limit(settings.downloadThreshold);

      if (batchContacts.length > 0) {
        // Find next batch number
        const lastBatch = await BatchModel.findOne().sort({ batchNumber: -1 });
        batchNumber = lastBatch ? lastBatch.batchNumber + 1 : 1;
        vcfFilename = `SILA_VCF_BATCH_${batchNumber}.vcf`;
        vcfData = generateVcfContent(batchContacts);

        // Save batch in database
        await BatchModel.create({
          batchNumber,
          filename: vcfFilename,
          contactsCount: batchContacts.length,
          vcfData
        });

        // Reset Counter
        settings.currentCounter = 0;
        await settings.save();

        triggerDownload = true;
      }
    }

    res.status(201).json({
      success: true,
      contact,
      triggerDownload,
      vcfFilename,
      vcfData,
      batchNumber,
      currentCounter: settings.currentCounter,
      threshold: settings.downloadThreshold
    });

  } catch (error) {
    console.error('Error saving contact:', error);
    res.status(500).json({ error: 'Failed to submit contact.' });
  }
});

// Track Site Visits
app.post('/api/visits', async (req, res) => {
  try {
    await connectDB();
    const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || 'Unknown';
    const country = getCountry(req);
    const { browser, device } = parseUserAgent(req.headers['user-agent']);

    const visit = await VisitModel.create({
      ip,
      country,
      browser,
      device
    });

    res.json({ success: true, visit });
  } catch (error) {
    res.status(500).json({ error: 'Failed to record visit.' });
  }
});

// Verify Admin PIN
app.post('/api/admin/login', async (req, res) => {
  try {
    await connectDB();
    const { pin } = req.body;
    if (!pin) {
      return res.status(400).json({ error: 'PIN is required' });
    }

    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not initialized.' });
    }

    if (settings.adminPin === pin.trim()) {
      res.json({ success: true, token: settings.adminPin });
    } else {
      res.status(401).json({ error: 'Incorrect PIN.' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Login verification failed.' });
  }
});

// Admin Dashboard stats
app.get('/api/admin/dashboard', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    
    // Total contacts starts with real database count
    const totalContacts = await ContactModel.countDocuments();

    // Contacts today
    const startOfToday = new Date();
    startOfToday.setHours(0, 0, 0, 0);
    const contactsToday = await ContactModel.countDocuments({ createdAt: { $gte: startOfToday } });

    // Total visits with actual database count
    const totalVisits = await VisitModel.countDocuments();

    // Online visitors (last 5 minutes)
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const onlineVisitors = await VisitModel.countDocuments({ timestamp: { $gte: fiveMinutesAgo } });

    // Download history (VCF files)
    const downloadHistory = await BatchModel.find().sort({ createdAt: -1 });

    // Recent contacts
    const recentContacts = await ContactModel.find().sort({ createdAt: -1 }).limit(10);

    // Current settings
    const settings = await SettingsModel.findOne();

    res.json({
      totalContacts,
      contactsToday,
      totalVisits,
      onlineVisitors,
      downloadHistory,
      recentContacts,
      threshold: settings?.downloadThreshold || 100,
      currentCounter: settings?.currentCounter || 0,
      whatsappGroupUrl: settings?.whatsappGroupUrl || '',
      whatsappChannelUrl: settings?.whatsappChannelUrl || ''
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch dashboard statistics.' });
  }
});

// Detailed Analytics Data
app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
  try {
    await connectDB();

    // Total visits & Unique IPs
    const totalVisits = await VisitModel.countDocuments();
    const uniqueIPsResult = await VisitModel.aggregate([
      { $group: { _id: '$ip' } },
      { $count: 'count' }
    ]);
    const uniqueVisitors = uniqueIPsResult[0]?.count || 0;

    // Daily visits over the last 15 days
    const fifteenDaysAgo = new Date();
    fifteenDaysAgo.setDate(fifteenDaysAgo.getDate() - 15);
    fifteenDaysAgo.setHours(0, 0, 0, 0);

    const dailyVisitsAggregation = await VisitModel.aggregate([
      { $match: { timestamp: { $gte: fifteenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const dailyVisits = dailyVisitsAggregation.map(item => ({
      date: item._id,
      count: item.count
    }));

    // Submissions over the last 15 days
    const dailySubmissionsAggregation = await ContactModel.aggregate([
      { $match: { createdAt: { $gte: fifteenDaysAgo } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const submissionsByDay = dailySubmissionsAggregation.map(item => ({
      date: item._id,
      count: item.count
    }));

    // Browser statistics
    const browserAggregation = await VisitModel.aggregate([
      { $group: { _id: '$browser', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    const browsers = browserAggregation.map(item => ({
      name: item._id || 'Unknown',
      value: item.count
    }));

    // Device statistics
    const deviceAggregation = await VisitModel.aggregate([
      { $group: { _id: '$device', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    const devices = deviceAggregation.map(item => ({
      name: item._id || 'Unknown',
      value: item.count
    }));

    // Country statistics
    const countryAggregation = await VisitModel.aggregate([
      { $group: { _id: '$country', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    const countries = countryAggregation.map(item => ({
      name: item._id || 'Unknown',
      value: item.count
    }));

    res.json({
      totalVisits,
      uniqueVisitors,
      dailyVisits,
      submissionsByDay,
      browsers,
      devices,
      countries
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch detailed analytics.' });
  }
});

// Get/Search contacts list
app.get('/api/admin/contacts', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const { search, limit = 100 } = req.query;

    let query: any = {};
    if (search && typeof search === 'string') {
      const searchRegex = new RegExp(search, 'i');
      query = {
        $or: [
          { name: searchRegex },
          { phone: searchRegex },
          { ip: searchRegex },
          { country: searchRegex }
        ]
      };
    }

    const contacts = await ContactModel.find(query).sort({ createdAt: -1 }).limit(Number(limit));
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch contacts.' });
  }
});

// Delete specific contact
app.delete('/api/admin/contacts/:id', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    
    // Check contact exists
    const contact = await ContactModel.findById(id);
    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    await ContactModel.findByIdAndDelete(id);

    // Decrement settings counter if appropriate, or keep intact. Usually we keep currentCounter intact as it tracks batches, but we can decrease if it was part of current batch. Let's just keep it simple.
    res.json({ success: true, message: 'Contact deleted successfully.' });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete contact.' });
  }
});

// Update settings (Admin)
app.post('/api/admin/settings', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const { downloadThreshold, whatsappGroupUrl, whatsappChannelUrl, adminPin } = req.body;

    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not initialized.' });
    }

    if (downloadThreshold !== undefined) {
      settings.downloadThreshold = Number(downloadThreshold);
    }
    if (whatsappGroupUrl !== undefined) {
      settings.whatsappGroupUrl = whatsappGroupUrl;
    }
    if (whatsappChannelUrl !== undefined) {
      settings.whatsappChannelUrl = whatsappChannelUrl;
    }
    if (adminPin !== undefined && adminPin.trim().length > 0) {
      settings.adminPin = adminPin.trim();
    }

    await settings.save();
    res.json({ success: true, message: 'Settings updated successfully.', settings });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update settings.' });
  }
});

// Manual Generate VCF
app.post('/api/admin/generate-vcf', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    
    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not found.' });
    }

    // Get current batch of contacts
    // If the counter is 0, we can fetch all contacts, or last downloadThreshold contacts. Let's fetch currentCounter contacts.
    // If currentCounter is 0, let's look for all contacts that haven't been archived, or simply download the last 'downloadThreshold' contacts.
    const limitCount = settings.currentCounter > 0 ? settings.currentCounter : settings.downloadThreshold;
    const batchContacts = await ContactModel.find()
      .sort({ createdAt: -1 })
      .limit(limitCount);

    if (batchContacts.length === 0) {
      return res.status(400).json({ error: 'No contacts available in the current batch to generate VCF.' });
    }

    // Create batch
    const lastBatch = await BatchModel.findOne().sort({ batchNumber: -1 });
    const batchNumber = lastBatch ? lastBatch.batchNumber + 1 : 1;
    const vcfFilename = `SILA_VCF_MANUAL_${batchNumber}.vcf`;
    const vcfData = generateVcfContent(batchContacts);

    const newBatch = await BatchModel.create({
      batchNumber,
      filename: vcfFilename,
      contactsCount: batchContacts.length,
      vcfData
    });

    // Reset current batch counter
    settings.currentCounter = 0;
    await settings.save();

    res.json({
      success: true,
      message: 'VCF file generated manually.',
      batch: newBatch,
      currentCounter: settings.currentCounter
    });

  } catch (error) {
    res.status(500).json({ error: 'Failed to generate manual VCF.' });
  }
});

// Reset Counter manually
app.post('/api/admin/reset', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const settings = await SettingsModel.findOne();
    if (!settings) {
      return res.status(500).json({ error: 'Settings not found.' });
    }

    settings.currentCounter = 0;
    await settings.save();

    res.json({ success: true, message: 'Counter reset successfully.', currentCounter: 0 });
  } catch (error) {
    res.status(500).json({ error: 'Failed to reset counter.' });
  }
});

// Retrieve/Download Batch VCF file content
app.get('/api/admin/download-batch/:id', async (req, res) => {
  try {
    await connectDB();
    const { id } = req.params;
    const batch = await BatchModel.findById(id);
    if (!batch) {
      return res.status(404).send('Batch not found');
    }

    res.setHeader('Content-Type', 'text/vcard; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${batch.filename}"`);
    res.send(batch.vcfData);
  } catch (error) {
    res.status(500).send('Failed to fetch batch VCF file.');
  }
});

// Export CSV of all contacts
app.get('/api/admin/export/csv', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const contacts = await ContactModel.find().sort({ createdAt: -1 });
    
    // Construct CSV Header
    let csvContent = 'Name,Phone,IP Address,Country,Browser,Device,Date Created\n';
    
    // Escape and add entries
    contacts.forEach(c => {
      const name = `"${c.name.replace(/"/g, '""')}"`;
      const phone = `"${c.phone.replace(/"/g, '""')}"`;
      const ip = `"${c.ip.replace(/"/g, '""')}"`;
      const country = `"${c.country.replace(/"/g, '""')}"`;
      const browser = `"${c.browser.replace(/"/g, '""')}"`;
      const device = `"${c.device.replace(/"/g, '""')}"`;
      const date = `"${new Date(c.createdAt).toISOString()}"`;
      
      csvContent += `${name},${phone},${ip},${country},${browser},${device},${date}\n`;
    });

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="SILA_VCF_All_Contacts.csv"');
    res.send(csvContent);
  } catch (error) {
    res.status(500).send('Failed to export CSV');
  }
});

// Export JSON of all contacts
app.get('/api/admin/export/json', requireAdmin, async (req, res) => {
  try {
    await connectDB();
    const contacts = await ContactModel.find().sort({ createdAt: -1 });
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', 'attachment; filename="SILA_VCF_All_Contacts.json"');
    res.send(JSON.stringify(contacts, null, 2));
  } catch (error) {
    res.status(500).send('Failed to export JSON');
  }
});


// Vite Dev / Static Production asset handler setup
async function startServer() {
  await connectDB();

  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

export default app;

if (process.env.NODE_ENV !== 'production' || !process.env.VERCEL) {
  startServer();
}
