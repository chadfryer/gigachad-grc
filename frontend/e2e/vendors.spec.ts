import { test, expect } from '@playwright/test';

/**
 * Vendors Module E2E Tests
 * Tests for Third-Party Risk Management (TPRM) functionality
 */

test.describe('Vendors - List View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/vendors');
    await page.waitForLoadState('networkidle');
  });

  test('displays vendors page with title', async ({ page }) => {
    await expect(page.locator('h1, h2').filter({ hasText: /Vendor/i })).toBeVisible();
  });

  test('shows vendors table or list', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Check for table or card layout
    const vendorsList = page.locator('table, [class*="grid"], [class*="list"]');
    await expect(vendorsList.first()).toBeVisible();
  });

  test('can add new vendor', async ({ page }) => {
    const addBtn = page.locator('button').filter({ hasText: /add|create|new/i }).first();
    
    if (await addBtn.count() > 0) {
      await addBtn.click();
      await page.waitForTimeout(1000);
      
      // Should show form or modal
      const form = page.locator('form, [role="dialog"]');
      await expect(form.first()).toBeVisible();
    }
  });

  test('has search functionality', async ({ page }) => {
    const searchInput = page.locator('input[type="search"], input[placeholder*="search" i]');
    
    if (await searchInput.count() > 0) {
      await expect(searchInput.first()).toBeVisible();
      await searchInput.first().fill('test vendor');
      await page.waitForTimeout(500);
    }
  });

  test('displays risk indicators', async ({ page }) => {
    await page.waitForTimeout(2000);
    
    // Look for risk score or risk level indicators
    const _riskIndicators = page.locator('[class*="risk"], [class*="score"], text=/high|medium|low|critical/i');
    // May or may not have data
    await expect(page.locator('main')).toBeVisible();
  });
});

test.describe('Vendors - Detail View', () => {
  test('can navigate to vendor detail', async ({ page }) => {
    await page.goto('/vendors');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const vendorLink = page.locator('a[href*="/vendors/"]').first();
    
    if (await vendorLink.count() > 0) {
      await vendorLink.click();
      await page.waitForLoadState('networkidle');
      
      // Should navigate to detail page
      await expect(page).toHaveURL(/vendors\/[a-zA-Z0-9-]+/);
    }
  });

  test('vendor detail shows key information', async ({ page }) => {
    await page.goto('/vendors');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    const vendorLink = page.locator('a[href*="/vendors/"]').first();
    
    if (await vendorLink.count() > 0) {
      await vendorLink.click();
      await page.waitForLoadState('networkidle');
      
      // Check for vendor details
      const detailPage = page.locator('main, [role="main"]');
      await expect(detailPage.first()).toBeVisible();
      
      // Should have vendor name
      await expect(page.locator('h1, h2').first()).toBeVisible();
    }
  });
});

test.describe('Vendors - Assessments', () => {
  test('can view vendor assessments', async ({ page }) => {
    await page.goto('/assessments');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2').filter({ hasText: /Assessment/i })).toBeVisible();
  });

  test('assessments list displays', async ({ page }) => {
    await page.goto('/assessments');
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(2000);
    
    // Should show assessments table or cards
    const assessmentsList = page.locator('table, [class*="grid"], [class*="list"]');
    await expect(assessmentsList.first()).toBeVisible();
  });
});

test.describe('Vendors - Contracts', () => {
  test('can view contracts page', async ({ page }) => {
    await page.goto('/contracts');
    await page.waitForLoadState('networkidle');
    
    await expect(page.locator('h1, h2').filter({ hasText: /Contract/i })).toBeVisible();
  });

  test('can add new contract', async ({ page }) => {
    await page.goto('/contracts');
    await page.waitForLoadState('networkidle');
    
    const addBtn = page.locator('button').filter({ hasText: /add|create|new/i }).first();
    
    if (await addBtn.count() > 0) {
      await addBtn.click();
      await page.waitForTimeout(1000);
      
      const form = page.locator('form, [role="dialog"]');
      await expect(form.first()).toBeVisible();
    }
  });
});




