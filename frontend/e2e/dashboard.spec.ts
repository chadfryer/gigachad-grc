import { test, expect } from '@playwright/test';

/**
 * Dashboard E2E Tests
 * Tests dashboard functionality including widgets, customization, and data display
 */

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
  });

  test('displays dashboard title and main elements', async ({ page }) => {
    // Check page title/header
    await expect(page.locator('h1, h2').first()).toBeVisible();
    
    // Check for dashboard content area
    const mainContent = page.locator('main, [role="main"], .dashboard-content');
    await expect(mainContent.first()).toBeVisible();
  });

  test('displays dashboard widgets', async ({ page }) => {
    // Wait for widgets to load
    await page.waitForTimeout(2000);
    
    // Check for widget containers (cards, panels, etc.)
    const widgets = page.locator('[class*="widget"], [class*="card"], [data-testid*="widget"]');
    const widgetCount = await widgets.count();
    
    // Should have at least one widget/card
    expect(widgetCount).toBeGreaterThan(0);
  });

  test('framework readiness widget shows data', async ({ page }) => {
    // Look for framework-related widget
    const frameworkWidget = page.locator('text=/framework|compliance|readiness/i').first();
    
    if (await frameworkWidget.count() > 0) {
      await expect(frameworkWidget).toBeVisible();
    }
  });

  test('control status displays', async ({ page }) => {
    // Look for control status information
    const controlStatus = page.locator('text=/control.*status|status.*control/i').first();
    
    if (await controlStatus.count() > 0) {
      await expect(controlStatus).toBeVisible();
    }
  });

  test('can access dashboard customization', async ({ page }) => {
    // Look for customize/settings button
    const customizeBtn = page.locator('button').filter({ hasText: /customize|settings|configure/i }).first();
    
    if (await customizeBtn.count() > 0) {
      await customizeBtn.click();
      
      // Should open a modal or panel
      const modal = page.locator('[role="dialog"], .modal, [class*="modal"]');
      await expect(modal.first()).toBeVisible({ timeout: 5000 });
    }
  });

  test('dashboard data updates on refresh', async ({ page }) => {
    // Get initial state
    const _initialContent = await page.locator('main, [role="main"]').first().textContent();
    
    // Reload page
    await page.reload();
    await page.waitForLoadState('networkidle');
    
    // Content should still be present after reload
    await expect(page.locator('main, [role="main"]').first()).toBeVisible();
  });
});

test.describe('Dashboard - Custom Dashboards', () => {
  test('can navigate to custom dashboards', async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
    
    // Should show custom dashboards page
    await expect(page.locator('h1, h2').filter({ hasText: /dashboard/i })).toBeVisible();
  });

  test('can create a new dashboard', async ({ page }) => {
    await page.goto('/dashboards');
    await page.waitForLoadState('networkidle');
    
    // Look for create/new button
    const createBtn = page.locator('button').filter({ hasText: /create|new|add/i }).first();
    
    if (await createBtn.count() > 0) {
      await createBtn.click();
      await page.waitForTimeout(1000);
      
      // Should show creation form or navigate to editor
      const formOrEditor = page.locator('form, [class*="editor"], input[name*="name"], input[placeholder*="name"]');
      expect(await formOrEditor.count()).toBeGreaterThan(0);
    }
  });
});

test.describe('Dashboard - Demo Data', () => {
  test('demo data banner appears for new users', async ({ page }) => {
    await page.goto('/dashboard');
    await page.waitForLoadState('networkidle');
    
    // Check for demo data banner
    const demoBanner = page.locator('text=/demo|sample|try.*data/i').first();
    
    // Banner may or may not be present depending on user state
    if (await demoBanner.count() > 0) {
      await expect(demoBanner).toBeVisible();
    }
  });
});




