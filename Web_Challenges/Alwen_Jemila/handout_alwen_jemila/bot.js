const puppeteer = require('puppeteer-core');

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const APP_URL = process.env.APP_URL || 'http://127.0.0.1:3000';
const BOT_INTERNAL_URL = process.env.BOT_INTERNAL_URL || APP_URL;
const BOT_TIMEOUT = parseInt(process.env.BOT_TIMEOUT) || 8000;

function findChromePath() {
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
    const context = await browser.createBrowserContext();
    const page = await context.newPage();

    try {
        await page.setViewport({ width: 1280, height: 720 });

        page.setDefaultNavigationTimeout(BOT_TIMEOUT);
        page.setDefaultTimeout(BOT_TIMEOUT);

        await page.goto(`${BOT_INTERNAL_URL}/login`, { waitUntil: 'networkidle2' });

        await page.type('input[name="username"]', ADMIN_USERNAME);
        await page.type('input[name="password"]', ADMIN_PASSWORD);
        await Promise.all([
            page.waitForNavigation({ waitUntil: 'networkidle2' }),
            page.click('button[type="submit"]'),
        ]);

        console.log('[Bot] Admin logged in successfully');

        if (!targetUrl.startsWith(APP_URL)) {
            console.log('[Bot] Invalid URL - must be on the same origin');
            await context.close();
            return { success: false, error: 'URL must be on the application domain' };
        }

        const internalUrl = targetUrl.replace(APP_URL, BOT_INTERNAL_URL);
        await page.goto(internalUrl, { waitUntil: 'networkidle2' });
        console.log('[Bot] Page loaded, waiting...');

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

process.on('exit', async () => {
    if (browserInstance) {
        await browserInstance.close();
    }
});

module.exports = { visitPage };
