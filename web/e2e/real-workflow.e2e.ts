import path from 'node:path';
import { expect, test } from '@playwright/test';

test('persists a project and connects a real alarm to CFG', async ({ page, request }) => {
  const projectName = `browser-e2e-${Date.now()}`;
  let projectId: string | undefined;

  try {
    await page.goto('/');
    await expect(page.getByText('真实 API', { exact: true })).toBeVisible();

    await page.getByRole('button', { name: '创建项目' }).click();
    await page.getByLabel('项目名称').fill(projectName);
    await page.locator('input[type="file"]').setInputFiles(
      path.resolve('../analyzer/tests/fixtures/c/simple_oob.c'),
    );
    await page.getByRole('button', { name: '创建项目' }).click();

    await expect(page).toHaveURL(/\/projects\/[^/]+$/);
    projectId = new URL(page.url()).pathname.split('/').pop();
    await expect(page.getByRole('heading', { name: projectName })).toBeVisible();
    await expect(page.getByText('1', { exact: true }).first()).toBeVisible();

    await page.getByRole('button', { name: '新建运行' }).click();
    const start = page.getByRole('button', { name: '启动分析' });
    await expect(start).toBeEnabled();
    await start.click();

    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]+$/);
    await expect(page.getByText('分析已完成')).toBeVisible({ timeout: 30_000 });
    await expect(page.getByText('1', { exact: true }).first()).toBeVisible();

    await page.getByRole('button', { name: /打开分析工作台/ }).click();
    await expect(page).toHaveURL(/\/runs\/[0-9a-f-]+\/workbench$/);
    await expect(page.getByText('1 个告警')).toBeVisible();
    await page.locator('.alarm-table-row').click();
    await expect(page.locator('.cfg-node.selected')).toContainText('bb0');
    await expect(page.locator('.code-line.line-active')).toContainText('buffer[8]');
    const stateToggle = page.getByLabel('切换 block state');
    await expect(stateToggle).toBeVisible();
    await expect(page.getByText('block state')).toBeHidden();
    await stateToggle.click();
    await expect(page.getByText('block state')).toBeVisible();

    await page.goto('/');
    await page.reload();
    await expect(page.getByRole('heading', { name: projectName })).toBeVisible();

    await page.getByRole('button', { name: `项目 ${projectName} 操作` }).click();
    await page.getByRole('menuitem', { name: '删除' }).click();
    const deleteDialog = page.getByRole('dialog', { name: '确认删除项目？' });
    await expect(deleteDialog).toContainText('删除后不可恢复');
    await deleteDialog.getByRole('button', { name: '确认删除' }).click();
    await expect(page.getByRole('heading', { name: projectName })).toHaveCount(0);
  } finally {
    if (projectId) await request.delete(`/api/v1/projects/${projectId}`);
  }
});
