interface ScreenshotParams {
  url: string;
  selector?: string;
  waitForSelector?: string;
  fullPage?: boolean;
  authentication?: {
    type: 'basic' | 'bearer' | 'cookie';
    credentials: Record<string, string>;
  };
}

interface ScreenshotResult {
  type: string;
  url: string;
  collectedAt: string;
  screenshot: string; // Base64 encoded image
  metadata: {
    width: number;
    height: number;
    format: string;
    size: number;
    captureTime: number;
  };
  pageInfo: {
    title: string;
    statusCode: number;
    loadTime: number;
  };
}

export async function captureScreenshot(params: ScreenshotParams): Promise<ScreenshotResult> {
  const {
    url,
    selector,
    waitForSelector,
    fullPage = false,
    authentication,
  } = params;

  const startTime = Date.now();

  try {
    // Dynamically import puppeteer to avoid loading it if not needed
    const puppeteer = await import('puppeteer');

    const browser = await puppeteer.default.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    });

    try {
      const page = await browser.newPage();
      
      // Set viewport
      await page.setViewport({
        width: 1920,
        height: 1080,
      });

      // Handle authentication
      if (authentication) {
        switch (authentication.type) {
          case 'basic':
            await page.authenticate({
              username: authentication.credentials.username,
              password: authentication.credentials.password,
            });
            break;
          case 'bearer':
            await page.setExtraHTTPHeaders({
              Authorization: `Bearer ${authentication.credentials.token}`,
            });
            break;
          case 'cookie': {
            const cookies = Object.entries(authentication.credentials).map(([name, value]) => ({
              name,
              value,
              url,
            }));
            await page.setCookie(...cookies);
            break;
          }
        }
      }

      // Navigate to URL
      const response = await page.goto(url, {
        waitUntil: 'networkidle2',
        timeout: 60000,
      });

      const loadTime = Date.now() - startTime;

      // Wait for specific selector if provided
      if (waitForSelector) {
        await page.waitForSelector(waitForSelector, { timeout: 30000 });
      }

      // Get page title
      const title = await page.title();
      const statusCode = response?.status() || 0;

      // Capture screenshot
      let screenshotBuffer: Buffer;
      
      if (selector) {
        const element = await page.$(selector);
        if (!element) {
          throw new Error(`Element not found: ${selector}`);
        }
        screenshotBuffer = await element.screenshot({
          type: 'png',
        }) as Buffer;
      } else {
        screenshotBuffer = await page.screenshot({
          type: 'png',
          fullPage,
        }) as Buffer;
      }

      const captureTime = Date.now() - startTime;

      // Get viewport dimensions
      const viewport = page.viewport();

      await browser.close();

      return {
        type: 'screenshot',
        url,
        collectedAt: new Date().toISOString(),
        screenshot: screenshotBuffer.toString('base64'),
        metadata: {
          width: viewport?.width || 1920,
          height: viewport?.height || 1080,
          format: 'png',
          size: screenshotBuffer.length,
          captureTime,
        },
        pageInfo: {
          title,
          statusCode,
          loadTime,
        },
      };
    } finally {
      await browser.close();
    }
  } catch {
    // Puppeteer not available or failed, return placeholder
    return {
      type: 'screenshot',
      url,
      collectedAt: new Date().toISOString(),
      screenshot: '', // Empty screenshot
      metadata: {
        width: 0,
        height: 0,
        format: 'png',
        size: 0,
        captureTime: Date.now() - startTime,
      },
      pageInfo: {
        title: 'Error',
        statusCode: 0,
        loadTime: 0,
      },
    };
  }
}




