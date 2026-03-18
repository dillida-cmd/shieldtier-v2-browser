#!/bin/bash
# =============================================================================
# ShieldTier API Server — One-Command Setup
# Run on your server: curl -sL <url> | bash
# Or: chmod +x setup.sh && ./setup.sh
#
# Prerequisites: Ubuntu 22.04+ with root/sudo access
# This script installs: Node.js 20, PostgreSQL 16, PM2, Nginx, Certbot
# Server sits behind Cloudflare → Nginx terminates local, CF handles SSL
# =============================================================================

set -e

DOMAIN="api.socbrowser.com"
APP_DIR="/opt/shieldtier-api"
DB_NAME="shieldtier"
DB_USER="shieldtier"
DB_PASS=$(openssl rand -hex 16)
PORT=3000

echo "═══════════════════════════════════════════════════"
echo " ShieldTier API Server Setup"
echo " Domain: $DOMAIN"
echo " App:    $APP_DIR"
echo " DB:     $DB_NAME"
echo "═══════════════════════════════════════════════════"
echo ""

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
echo "[1/7] Installing system packages..."
apt-get update -qq
apt-get install -y -qq curl gnupg2 nginx

# Node.js 20
if ! command -v node &>/dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
fi
echo "  Node $(node --version)"

# PostgreSQL 16
if ! command -v psql &>/dev/null; then
    sh -c 'echo "deb http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" > /etc/apt/sources.list.d/pgdg.list'
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/trusted.gpg.d/postgresql.gpg
    apt-get update -qq
    apt-get install -y -qq postgresql-16
fi
echo "  PostgreSQL $(psql --version | awk '{print $3}')"

# PM2
if ! command -v pm2 &>/dev/null; then
    npm install -g pm2
fi
echo "  PM2 $(pm2 --version)"

# ---------------------------------------------------------------------------
# 2. Database setup
# ---------------------------------------------------------------------------
echo ""
echo "[2/7] Setting up PostgreSQL..."

sudo -u postgres psql -tc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE USER $DB_USER WITH PASSWORD '$DB_PASS';"

sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" | grep -q 1 || \
    sudo -u postgres psql -c "CREATE DATABASE $DB_NAME OWNER $DB_USER;"

sudo -u postgres psql -d "$DB_NAME" -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;"

# Create tables
sudo -u postgres psql -d "$DB_NAME" << 'SQL'

CREATE TABLE IF NOT EXISTS releases (
    id SERIAL PRIMARY KEY,
    version VARCHAR(20) NOT NULL,
    platform VARCHAR(20) NOT NULL,
    arch VARCHAR(10) NOT NULL,
    download_url TEXT NOT NULL,
    file_size BIGINT DEFAULT 0,
    sha256 VARCHAR(64),
    release_notes TEXT,
    min_os_version VARCHAR(20),
    is_critical BOOLEAN DEFAULT FALSE,
    published_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(version, platform, arch)
);

CREATE TABLE IF NOT EXISTS feedback (
    id SERIAL PRIMARY KEY,
    type VARCHAR(20) NOT NULL DEFAULT 'general',
    message TEXT NOT NULL,
    email VARCHAR(255),
    rating INT CHECK (rating IS NULL OR (rating BETWEEN 1 AND 5)),
    version VARCHAR(20),
    platform VARCHAR(20),
    arch VARCHAR(20),
    user_email VARCHAR(255),
    user_name VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    read BOOLEAN DEFAULT FALSE,
    responded BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS telemetry (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50) NOT NULL,
    version VARCHAR(20),
    platform VARCHAR(20),
    arch VARCHAR(20),
    data JSONB,
    ip_address INET,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_releases_platform ON releases(platform, arch);
CREATE INDEX IF NOT EXISTS idx_feedback_created ON feedback(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_feedback_unread ON feedback(read) WHERE read = FALSE;
CREATE INDEX IF NOT EXISTS idx_telemetry_event ON telemetry(event_type, created_at DESC);

-- Seed initial release (update URLs when you have actual builds)
INSERT INTO releases (version, platform, arch, download_url, release_notes) VALUES
    ('2.0.0', 'macos',   'arm64', 'https://releases.socbrowser.com/ShieldTier-2.0.0-macos-arm64.dmg',      'Initial release'),
    ('2.0.0', 'macos',   'x64',   'https://releases.socbrowser.com/ShieldTier-2.0.0-macos-x64.dmg',        'Initial release'),
    ('2.0.0', 'windows', 'x64',   'https://releases.socbrowser.com/ShieldTier-2.0.0-windows-x64-setup.exe','Initial release'),
    ('2.0.0', 'windows', 'arm64', 'https://releases.socbrowser.com/ShieldTier-2.0.0-windows-arm64-setup.exe','Initial release'),
    ('2.0.0', 'linux',   'x64',   'https://releases.socbrowser.com/ShieldTier-2.0.0-linux-x64.AppImage',   'Initial release'),
    ('2.0.0', 'linux',   'arm64', 'https://releases.socbrowser.com/ShieldTier-2.0.0-linux-arm64.AppImage', 'Initial release')
ON CONFLICT (version, platform, arch) DO NOTHING;

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO shieldtier;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO shieldtier;

SQL

echo "  Database ready."

# ---------------------------------------------------------------------------
# 3. Application code
# ---------------------------------------------------------------------------
echo ""
echo "[3/7] Deploying application..."

mkdir -p "$APP_DIR"

cat > "$APP_DIR/package.json" << 'PKGJSON'
{
  "name": "shieldtier-api",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "start": "node server.js"
  },
  "dependencies": {
    "express": "^4.21.0",
    "pg": "^8.13.0",
    "helmet": "^8.0.0",
    "cors": "^2.8.5",
    "express-rate-limit": "^7.4.0"
  }
}
PKGJSON

cat > "$APP_DIR/server.js" << 'SERVERJS'
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Middleware ──
app.use(helmet());
app.use(cors({ origin: '*' }));  // Cloudflare handles CORS at edge if needed
app.use(express.json({ limit: '1mb' }));

// Trust Cloudflare proxy headers
app.set('trust proxy', true);

// Rate limiting — per IP via CF-Connecting-IP
const getIP = (req) => req.headers['cf-connecting-ip'] || req.headers['x-forwarded-for'] || req.ip;

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,
    keyGenerator: getIP,
    standardHeaders: true,
    legacyHeaders: false,
});

const feedbackLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,  // 1 hour
    max: 10,                    // 10 feedback submissions per hour
    keyGenerator: getIP,
    message: { error: 'Too many feedback submissions. Please try again later.' },
});

app.use('/v1/', generalLimiter);

// ── Database ──
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
});

// Health check (Cloudflare uptime monitoring)
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ═══════════════════════════════════════════════════════
// UPDATE CHECK
// GET /v1/update/check?version=2.0.0&platform=macos&arch=arm64
// ═══════════════════════════════════════════════════════

app.get('/v1/update/check', async (req, res) => {
    try {
        const { version, platform, arch } = req.query;

        if (!version || !platform) {
            return res.status(400).json({ error: 'version and platform required' });
        }

        const { rows } = await db.query(
            `SELECT version, download_url, file_size, sha256, release_notes, is_critical
             FROM releases
             WHERE platform = $1 AND arch = $2
             ORDER BY published_at DESC LIMIT 1`,
            [platform, arch || 'x64']
        );

        // Log the check (anonymous telemetry)
        db.query(
            `INSERT INTO telemetry (event_type, version, platform, arch, ip_address)
             VALUES ('update_check', $1, $2, $3, $4)`,
            [version, platform, arch || 'x64', getIP(req)]
        ).catch(() => {});  // fire and forget

        if (rows.length === 0) {
            return res.json({
                updateAvailable: false,
                latestVersion: version,
            });
        }

        const latest = rows[0];
        const updateAvailable = latest.version !== version;

        res.json({
            updateAvailable,
            latestVersion: latest.version,
            downloadUrl: updateAvailable ? latest.download_url : '',
            fileSize: parseInt(latest.file_size) || 0,
            sha256: latest.sha256 || '',
            releaseNotes: latest.release_notes || '',
            isCritical: latest.is_critical || false,
        });
    } catch (err) {
        console.error('Update check error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════
// FEEDBACK
// POST /v1/feedback
// ═══════════════════════════════════════════════════════

app.post('/v1/feedback', feedbackLimiter, async (req, res) => {
    try {
        const { type, message, email, rating, version, platform, userEmail, userName } = req.body;

        if (!message || !message.trim()) {
            return res.status(400).json({ error: 'Message is required' });
        }

        if (message.length > 5000) {
            return res.status(400).json({ error: 'Message too long (max 5000 chars)' });
        }

        const ip = getIP(req);
        const ua = req.headers['user-agent'] || '';

        await db.query(
            `INSERT INTO feedback
                (type, message, email, rating, version, platform, user_email, user_name, ip_address, user_agent)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
            [
                type || 'general',
                message.trim(),
                email || null,
                rating || null,
                version || null,
                platform || null,
                userEmail || null,
                userName || null,
                ip,
                ua,
            ]
        );

        res.json({ received: true });
    } catch (err) {
        console.error('Feedback error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════
// APP INFO
// GET /v1/app/info
// ═══════════════════════════════════════════════════════

app.get('/v1/app/info', (req, res) => {
    res.json({
        name: 'ShieldTier',
        website: 'https://socbrowser.com',
        support: 'support@socbrowser.com',
        github: 'https://github.com/dillida/shieldtier-v2-browser',
        docs: 'https://docs.socbrowser.com',
        community: 'https://discord.gg/shieldtier',
    });
});

// ═══════════════════════════════════════════════════════
// ADMIN — Push new release (protect with auth in production)
// POST /v1/admin/release
// Header: X-Admin-Key: <your-secret>
// ═══════════════════════════════════════════════════════

const ADMIN_KEY = process.env.ADMIN_KEY || '';

app.post('/v1/admin/release', async (req, res) => {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    try {
        const { version, releaseNotes, isCritical, platforms } = req.body;
        // platforms: [{ platform, arch, downloadUrl, fileSize, sha256 }]

        if (!version || !platforms || !Array.isArray(platforms)) {
            return res.status(400).json({ error: 'version and platforms[] required' });
        }

        for (const p of platforms) {
            await db.query(
                `INSERT INTO releases (version, platform, arch, download_url, file_size, sha256, release_notes, is_critical)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (version, platform, arch) DO UPDATE SET
                     download_url = EXCLUDED.download_url,
                     file_size = EXCLUDED.file_size,
                     sha256 = EXCLUDED.sha256,
                     release_notes = EXCLUDED.release_notes,
                     is_critical = EXCLUDED.is_critical,
                     published_at = NOW()`,
                [
                    version,
                    p.platform,
                    p.arch || 'x64',
                    p.downloadUrl,
                    p.fileSize || 0,
                    p.sha256 || '',
                    releaseNotes || '',
                    isCritical || false,
                ]
            );
        }

        res.json({ published: true, version, platformCount: platforms.length });
    } catch (err) {
        console.error('Release publish error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════
// ADMIN — View feedback
// GET /v1/admin/feedback?unread=true&limit=50
// ═══════════════════════════════════════════════════════

app.get('/v1/admin/feedback', async (req, res) => {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    try {
        const unread = req.query.unread === 'true';
        const limit = Math.min(parseInt(req.query.limit) || 50, 200);

        let query = 'SELECT * FROM feedback';
        const params = [];
        if (unread) {
            query += ' WHERE read = FALSE';
        }
        query += ' ORDER BY created_at DESC LIMIT $' + (params.length + 1);
        params.push(limit);

        const { rows } = await db.query(query, params);

        // Mark as read
        if (unread && rows.length > 0) {
            const ids = rows.map(r => r.id);
            await db.query('UPDATE feedback SET read = TRUE WHERE id = ANY($1)', [ids]);
        }

        res.json({
            total: rows.length,
            feedback: rows,
        });
    } catch (err) {
        console.error('Feedback list error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ═══════════════════════════════════════════════════════
// ADMIN — Telemetry stats
// GET /v1/admin/stats
// ═══════════════════════════════════════════════════════

app.get('/v1/admin/stats', async (req, res) => {
    if (!ADMIN_KEY || req.headers['x-admin-key'] !== ADMIN_KEY) {
        return res.status(403).json({ error: 'Forbidden' });
    }

    try {
        const [checks, fb, platforms, versions] = await Promise.all([
            db.query("SELECT COUNT(*) as count FROM telemetry WHERE event_type = 'update_check' AND created_at > NOW() - INTERVAL '24 hours'"),
            db.query("SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE read = FALSE) as unread FROM feedback"),
            db.query("SELECT platform, arch, COUNT(*) as count FROM telemetry WHERE event_type = 'update_check' GROUP BY platform, arch ORDER BY count DESC"),
            db.query("SELECT version, COUNT(*) as count FROM telemetry WHERE event_type = 'update_check' GROUP BY version ORDER BY count DESC LIMIT 10"),
        ]);

        res.json({
            updateChecks24h: parseInt(checks.rows[0].count),
            feedback: {
                total: parseInt(fb.rows[0].total),
                unread: parseInt(fb.rows[0].unread),
            },
            platformBreakdown: platforms.rows,
            versionBreakdown: versions.rows,
        });
    } catch (err) {
        console.error('Stats error:', err.message);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// ── Start ──
app.listen(PORT, '127.0.0.1', () => {
    console.log(`ShieldTier API running on port ${PORT}`);
});
SERVERJS

cd "$APP_DIR" && npm install --production
echo "  Application deployed."

# ---------------------------------------------------------------------------
# 4. Environment file
# ---------------------------------------------------------------------------
echo ""
echo "[4/7] Creating environment config..."

cat > "$APP_DIR/.env" << ENVFILE
DATABASE_URL=postgresql://${DB_USER}:${DB_PASS}@localhost:5432/${DB_NAME}
PORT=${PORT}
ADMIN_KEY=$(openssl rand -hex 32)
NODE_ENV=production
ENVFILE

chmod 600 "$APP_DIR/.env"
echo "  .env created."

# ---------------------------------------------------------------------------
# 5. PM2 process manager
# ---------------------------------------------------------------------------
echo ""
echo "[5/7] Setting up PM2..."

cat > "$APP_DIR/ecosystem.config.js" << 'PM2CFG'
module.exports = {
    apps: [{
        name: 'shieldtier-api',
        script: 'server.js',
        cwd: '/opt/shieldtier-api',
        instances: 2,
        exec_mode: 'cluster',
        env: {
            NODE_ENV: 'production',
        },
        env_file: '/opt/shieldtier-api/.env',
        max_memory_restart: '256M',
        log_date_format: 'YYYY-MM-DD HH:mm:ss',
        error_file: '/var/log/shieldtier-api/error.log',
        out_file: '/var/log/shieldtier-api/access.log',
        merge_logs: true,
    }]
};
PM2CFG

mkdir -p /var/log/shieldtier-api

# Source env and start
set -a; source "$APP_DIR/.env"; set +a
cd "$APP_DIR"
pm2 delete shieldtier-api 2>/dev/null || true
pm2 start ecosystem.config.js
pm2 save
pm2 startup systemd -u root --hp /root 2>/dev/null || true
echo "  PM2 running."

# ---------------------------------------------------------------------------
# 6. Nginx reverse proxy (Cloudflare → Nginx → Node)
# ---------------------------------------------------------------------------
echo ""
echo "[6/7] Configuring Nginx..."

cat > "/etc/nginx/sites-available/shieldtier-api" << NGINX
# ShieldTier API — behind Cloudflare
# Cloudflare handles SSL termination, Nginx proxies to Node.js

server {
    listen 80;
    server_name ${DOMAIN};

    # Cloudflare real IP restoration
    set_real_ip_from 103.21.244.0/22;
    set_real_ip_from 103.22.200.0/22;
    set_real_ip_from 103.31.4.0/22;
    set_real_ip_from 104.16.0.0/13;
    set_real_ip_from 104.24.0.0/14;
    set_real_ip_from 108.162.192.0/18;
    set_real_ip_from 131.0.72.0/22;
    set_real_ip_from 141.101.64.0/18;
    set_real_ip_from 162.158.0.0/15;
    set_real_ip_from 172.64.0.0/13;
    set_real_ip_from 173.245.48.0/20;
    set_real_ip_from 188.114.96.0/20;
    set_real_ip_from 190.93.240.0/20;
    set_real_ip_from 197.234.240.0/22;
    set_real_ip_from 198.41.128.0/17;
    set_real_ip_from 2400:cb00::/32;
    set_real_ip_from 2606:4700::/32;
    set_real_ip_from 2803:f800::/32;
    set_real_ip_from 2405:b500::/32;
    set_real_ip_from 2405:8100::/32;
    set_real_ip_from 2c0f:f248::/32;
    set_real_ip_from 2a06:98c0::/29;
    real_ip_header CF-Connecting-IP;

    # Security headers (Cloudflare adds some, but belt+suspenders)
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;

    # API proxy
    location /v1/ {
        proxy_pass http://127.0.0.1:${PORT};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_read_timeout 30s;
        proxy_send_timeout 30s;
    }

    location /health {
        proxy_pass http://127.0.0.1:${PORT};
    }

    location / {
        return 404 '{"error":"not found"}';
        add_header Content-Type application/json;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/shieldtier-api /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default 2>/dev/null
nginx -t && systemctl reload nginx
echo "  Nginx configured."

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------
echo ""
echo "═══════════════════════════════════════════════════"
echo " SETUP COMPLETE"
echo "═══════════════════════════════════════════════════"
echo ""
echo " API Server:  http://${DOMAIN}/v1/"
echo " Health:      http://${DOMAIN}/health"
echo " App Dir:     ${APP_DIR}"
echo " Logs:        /var/log/shieldtier-api/"
echo ""
echo " Database:"
echo "   Name:      ${DB_NAME}"
echo "   User:      ${DB_USER}"
echo "   Password:  ${DB_PASS}"
echo ""

ADMIN_KEY=$(grep ADMIN_KEY "$APP_DIR/.env" | cut -d= -f2)
echo " Admin Key:   ${ADMIN_KEY}"
echo "   (save this — needed for publishing releases and viewing feedback)"
echo ""
echo " ── Cloudflare Setup ──"
echo "   1. Add A record: ${DOMAIN} → your server IP"
echo "   2. Proxy status: Proxied (orange cloud)"
echo "   3. SSL/TLS: Full (not Full Strict, unless you add origin cert)"
echo "   4. Under Caching → Configuration: Bypass cache for /v1/*"
echo ""
echo " ── Test ──"
echo "   curl http://${DOMAIN}/health"
echo "   curl http://${DOMAIN}/v1/update/check?version=2.0.0&platform=macos&arch=arm64"
echo "   curl -X POST http://${DOMAIN}/v1/feedback -H 'Content-Type: application/json' -d '{\"type\":\"general\",\"message\":\"test\"}'"
echo ""
echo " ── Admin ──"
echo "   # View feedback:"
echo "   curl -H 'X-Admin-Key: ${ADMIN_KEY}' http://${DOMAIN}/v1/admin/feedback"
echo ""
echo "   # View stats:"
echo "   curl -H 'X-Admin-Key: ${ADMIN_KEY}' http://${DOMAIN}/v1/admin/stats"
echo ""
echo "   # Push new release:"
echo "   curl -X POST -H 'X-Admin-Key: ${ADMIN_KEY}' -H 'Content-Type: application/json' \\"
echo "     http://${DOMAIN}/v1/admin/release -d '{"
echo "       \"version\": \"2.1.0\","
echo "       \"releaseNotes\": \"Bug fixes\","
echo "       \"platforms\": ["
echo "         {\"platform\":\"macos\",\"arch\":\"arm64\",\"downloadUrl\":\"https://releases.socbrowser.com/ShieldTier-2.1.0-macos-arm64.dmg\"},"
echo "         {\"platform\":\"windows\",\"arch\":\"x64\",\"downloadUrl\":\"https://releases.socbrowser.com/ShieldTier-2.1.0-windows-x64-setup.exe\"},"
echo "         {\"platform\":\"linux\",\"arch\":\"x64\",\"downloadUrl\":\"https://releases.socbrowser.com/ShieldTier-2.1.0-linux-x64.AppImage\"}"
echo "       ]"
echo "     }'"
echo ""
echo "═══════════════════════════════════════════════════"
