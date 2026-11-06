import { expect, test } from '@playwright/test';

const apiKey = 'scadaver-e2e-loopback-only';

async function guardedJson(page, path, body) {
  return page.evaluate(
    async ({ requestPath, requestBody, key }) => {
      const response = await fetch(requestPath, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Key': key,
        },
        body: JSON.stringify(requestBody),
      });
      return { status: response.status, body: await response.json() };
    },
    { requestPath: path, requestBody: body, key: apiKey },
  );
}

test('renders the controlled loopback interface and complete protocol catalog', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  const interfaceSelect = page.locator('select[x-model="selectedIface"]');
  await expect(interfaceSelect).toHaveValue('127.0.0.1');
  await expect(interfaceSelect.locator('option')).toHaveCount(1);
  await expect(interfaceSelect.locator('option')).toHaveText('SCADAver test loopback (127.0.0.1 / 255.255.255.255)');

  const protocolSelect = page.locator('select[x-model="scanVendor"]');
  await expect(protocolSelect).toContainText('Modbus TCP');
  await expect(protocolSelect).toContainText('BACnet/IP');
  await expect(protocolSelect).toContainText('OPC UA');
  await expect(page.locator('input[x-model="scanPort"]')).toBeVisible();
});

test('blocks malformed subnet input in the browser before a network request', async ({ page }) => {
  let scanRequestSeen = false;
  page.on('request', request => {
    if (new URL(request.url()).pathname === '/api/scan') {
      scanRequestSeen = true;
    }
  });

  await page.goto(`/?key=${apiKey}`);
  await page.locator('input[x-model="scanTarget"]').fill('10.x.x.x/24');
  await page.getByRole('button', { name: 'Scan Network' }).click();

  await expect(page.locator('[x-text="toast?.msg"]')).toContainText('Target subnet must be an IPv4 CIDR');
  expect(scanRequestSeen).toBe(false);
});

test('loopback harness rejects non-loopback API targets before a scan starts', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  const scan = await guardedJson(page, '/api/scan', {
    vendor: 'modbus',
    timeout: 1,
    iface_ip: '127.0.0.1',
    target_cidr: '10.2.10.0/24',
  });
  expect(scan.status).toBe(400);
  expect(scan.body.error).toContain('SCADAVER_TEST_LOOPBACK=1 only permits');

  const probe = await guardedJson(page, '/api/scan/ip', {
    ip: '10.2.10.25',
    timeout: 1,
  });
  expect(probe.status).toBe(400);
  expect(probe.body.error).toContain('SCADAVER_TEST_LOOPBACK=1 only permits');
});

test('the API rejects invalid reserved port overrides without scanning', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  const result = await guardedJson(page, '/api/scan', {
    vendor: 'modbus',
    timeout: 1,
    iface_ip: '127.0.0.1',
    target_cidr: '127.0.0.1/32',
    target_port: 0,
  });
  expect(result.status).toBe(400);
  expect(result.body.error).toBe('Target port must be between 1 and 65535');
});

test('finds the high-port Modbus simulator through the scanner UI', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  await page.locator('select[x-model="scanVendor"]').selectOption('modbus');
  await page.locator('input[x-model="scanTarget"]').fill('127.0.0.1/32');
  const portInput = page.locator('input[x-model="scanPort"]');
  await expect(portInput).toBeEnabled();
  await portInput.fill('1502');
  await page.getByRole('button', { name: 'Scan Network' }).click();

  const result = page.locator('tbody tr').filter({ hasText: '127.0.0.1' });
  await expect(result).toContainText('modbus', { timeout: 15_000 });
  await expect(result).toContainText('TCP 1502');

  await result.getByRole('button', { name: '+ Add' }).click();
  const savedDevice = page.locator('aside').getByText('127.0.0.1', { exact: true });
  await expect(savedDevice).toBeVisible();
  await savedDevice.click();
  await page.getByRole('button', { name: 'tags', exact: true }).click();
  await page.getByRole('button', { name: 'Re-pull (live)', exact: true }).click();

  const holdingRegister = page.locator('tbody tr').filter({ hasText: 'hr:0' });
  await expect(holdingRegister).toContainText('0', { timeout: 15_000 });
  await expect(page.locator('p[x-show="tagsReadOnly()"]')).toContainText('Modbus');
  await expect(holdingRegister.locator('span')).toHaveClass(/text-slate-400/);
});

test('finds the high-port Beckhoff ADS simulator and keeps its tags read-only', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  await page.locator('select[x-model="scanVendor"]').selectOption('beckhoff');
  await page.locator('input[x-model="scanTarget"]').fill('127.0.0.1/32');
  const portInput = page.locator('input[x-model="scanPort"]');
  await expect(portInput).toBeEnabled();
  await portInput.fill('14898');
  await page.getByRole('button', { name: 'Scan Network' }).click();

  const result = page.locator('tbody tr').filter({ hasText: '127.0.0.1' });
  await expect(result).toContainText('beckhoff', { timeout: 15_000 });
  await expect(result).toContainText('TCP 14898');

  await result.getByRole('button', { name: '+ Add' }).click();
  const savedDevice = page.locator('aside').getByText('127.0.0.1', { exact: true });
  await expect(savedDevice).toBeVisible();
  await savedDevice.click();
  await page.getByRole('button', { name: 'tags', exact: true }).click();
  await page.getByRole('button', { name: 'Re-pull (live)', exact: true }).click();

  const counter = page.locator('tbody tr').filter({ hasText: 'MAIN.counter' });
  await expect(counter).toContainText('1234', { timeout: 15_000 });
  await expect(page.locator('p[x-show="tagsReadOnly()"]')).toContainText('Beckhoff ADS');
  await expect(counter.locator('span')).toHaveClass(/text-slate-400/);
});

test('finds the high-port Mitsubishi SLMP simulator and keeps its tags read-only', async ({ page }) => {
  await page.goto(`/?key=${apiKey}`);

  await page.locator('select[x-model="scanVendor"]').selectOption('mitsubishi');
  await page.locator('input[x-model="scanTarget"]').fill('127.0.0.1/32');
  const portInput = page.locator('input[x-model="scanPort"]');
  await expect(portInput).toBeEnabled();
  await portInput.fill('15007');
  await page.getByRole('button', { name: 'Scan Network' }).click();

  const result = page.locator('tbody tr').filter({ hasText: '127.0.0.1' });
  await expect(result).toContainText('mitsubishi', { timeout: 15_000 });
  await expect(result).toContainText('TCP 15007');

  await result.getByRole('button', { name: '+ Add' }).click();
  const savedDevice = page.locator('aside').getByText('127.0.0.1', { exact: true });
  await expect(savedDevice).toBeVisible();
  await savedDevice.click();
  await page.getByRole('button', { name: 'tags', exact: true }).click();
  await page.getByRole('button', { name: 'Re-pull (live)', exact: true }).click();

  const d0 = page.locator('tbody tr').filter({ hasText: 'D0' });
  const m0 = page.locator('tbody tr').filter({ hasText: 'M0' });
  await expect(d0).toContainText('0', { timeout: 15_000 });
  await expect(m0).toContainText('OFF', { timeout: 15_000 });
  await expect(page.locator('p[x-show="tagsReadOnly()"]')).toContainText('Mitsubishi SLMP');
  await expect(d0.locator('span')).toHaveClass(/text-slate-400/);

  await page.getByRole('button', { name: 'exploits', exact: true }).click();
  await expect(page.getByText('No exploits defined for this vendor.')).toBeVisible();
});
