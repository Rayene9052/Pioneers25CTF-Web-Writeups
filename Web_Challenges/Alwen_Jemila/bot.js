/**
 * Admin Bot - ChromaLeak
 * 
 * Simulates an admin visiting reported pages.
 * The admin logs in first, then navigates to the reported URL.
 */

const puppeteer = require('puppeteer-core');

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const APP_URL = process.env.APP_URL || 'http://127.0.0.1:3000';
// BOT_INTERNAL_URL: the URL the bot uses to actually navigate (inside Docker = localhost)
// This avoids requiring the container to resolve the public domain.
const BOT_INTERNAL_URL = process.env.BOT_INTERNAL_URL || APP_URL;
const BOT_TIMEOUT = parseInt(process.env.BOT_TIMEOUT) || 8000;

// Find Chrome/Chromium executable
function findChromePath() {
    // Environment variable override (used in Docker)
    if (process.env.PUPPETEER_EXECUTABLE_PATH) {
        return process.env.PUPPETEER_EXECUTABLE_PATH;
    }

    const fs = require('fs');
    const paths = process.platform === 'win32'
        ? [
            'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
            process.env.LOCALAPPDATA + '\\Google\\Chrome\\Application\\chrome.exe',
            'C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe',
          ]
        : [
            '/usr/bin/chromium-browser',
            '/usr/bin/chromium',
            '/usr/bin/google-chrome',
            '/usr/bin/google-chrome-stable',
          ];

    for (const p of paths) {
        try { if (fs.existsSync(p)) return p; } catch {}
    }
    throw new Error('Chrome/Chromium not found. Set PUPPETEER_EXECUTABLE_PATH.');
}

let browserInstance = null;

async function getBrowser() {
    if (!browserInstance) {
        const executablePath = findChromePath();
        console.log(`[Bot] Using browser: ${executablePath}`);
        browserInstance = await puppeteer.launch({
            headless: 'new',
            executablePath,
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-background-networking',
                '--disable-default-apps',
                '--disable-sync',
                '--disable-translate',
                '--metrics-recording-only',
                '--no-first-run',
            ],
        });
    }
    return browserInstance;
}

async function visitPage(targetUrl) {
    console.log(`[Bot] Admin visiting: ${targetUrl}`);
    
    const browser = await getBrowser();
    // Use a fresh incognito context so session cookies don't persist between visits
    const context = await browser.createBrowserContext();
    const page = await context.newPage();

    try {
        // Set viewport
        await page.setViewport({ width: 1280, height: 720 });

        // Set a reasonable timeout
        page.setDefaultNavigationTimeout(BOT_TIMEOUT);
        page.setDefaultTimeout(BOT_TIMEOUT);

        // Step 1: Navigate to login page (uses internal URL)
        await page.goto(`${BOT_INTERNAL_URL}/login`, { waitUntil: 'networkidle2' });

        // Step 2: Log in as admin
        await page.type('input[name="username"]', ADMIN_USERNAME);
        await page.type('input[name="password"]', ADMIN_PASSWORD);
        await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle2' }),
            page.click('button[type="submit"]'),
        ]);

        console.log('[Bot] Admin logged in successfully');

        // Step 3: Validate the target URL (must start with public APP_URL)
        if (!targetUrl.startsWith(APP_URL)) {
            console.log('[Bot] Invalid URL - must be on the same origin');
            await context.close();
            return { success: false, error: 'URL must be on the application domain' };
        }

        // Step 4: Visit the target URL (rewrite public URL to internal)
        const internalUrl = targetUrl.replace(APP_URL, BOT_INTERNAL_URL);
        await page.goto(internalUrl, { waitUntil: 'networkidle2' });
        console.log('[Bot] Page loaded, waiting...');

        // Step 5: Wait for potential CSS loads (images, fonts, etc.)
        await new Promise(resolve => setTimeout(resolve, 5000));

        console.log('[Bot] Visit complete');
        await context.close();
        return { success: true };

    } catch (error) {
        console.error(`[Bot] Error: ${error.message}`);
        try { await context.close(); } catch (e) {}
        return { success: false, error: error.message };
    }
}

// Cleanup on process exit
process.on('exit', async () => {
    if (browserInstance) {
        await browserInstance.close();
    }
});

module.exports = { visitPage };
