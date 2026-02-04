import { test as setup, expect } from '@playwright/test';

const authFile = 'playwright/.auth/user.json';

/**
 * Authentication setup - runs once before all tests
 * This handles login and stores the auth state for reuse
 */
setup('authenticate', async ({ page }) => {
  // Navigate to login page
  await page.goto('/login');

  // Wait for the page to load
  await page.waitForLoadState('networkidle');

  // Check if we're already logged in (redirected to dashboard)
  const currentUrl = page.url();
  if (currentUrl.includes('/dashboard') || currentUrl.includes('/')) {
    // Already authenticated, save state and continue
    await page.context().storageState({ path: authFile });
    return;
  }

  // If using Keycloak, handle the Keycloak login form
  // Check for Keycloak login form
  const keycloakLogin = page.locator('#username, #kc-login');
  if ((await keycloakLogin.count()) > 0) {
    // Fill in Keycloak credentials
    if (!process.env.E2E_USERNAME || !process.env.E2E_PASSWORD) {
      throw new Error('E2E_USERNAME and E2E_PASSWORD environment variables are required');
    }
    await page.fill('#username', process.env.E2E_USERNAME);
    await page.fill('#password', process.env.E2E_PASSWORD);
    await page.click('#kc-login');

    // Wait for redirect back to app
    await page.waitForURL(/\/(dashboard|$)/, { timeout: 30000 });
  }

  // If using local auth form
  const localLogin = page.locator('input[name="email"], input[type="email"]');
  if ((await localLogin.count()) > 0) {
    if (!process.env.E2E_USERNAME || !process.env.E2E_PASSWORD) {
      throw new Error('E2E_USERNAME and E2E_PASSWORD environment variables are required');
    }
    await page.fill('input[name="email"], input[type="email"]', process.env.E2E_USERNAME);
    await page.fill('input[name="password"], input[type="password"]', process.env.E2E_PASSWORD);
    await page.click('button[type="submit"]');

    // Wait for navigation
    await page.waitForURL(/\/(dashboard|$)/, { timeout: 30000 });
  }

  // Verify we're logged in
  await expect(page).toHaveURL(/\/(dashboard|$)/);

  // Save authentication state
  await page.context().storageState({ path: authFile });
});
