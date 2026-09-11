/** Pure geometry helpers behind the resizable workbench columns. */

export const SPLITTER_WIDTH = 6;
export const MIN_PANE_WIDTH = 220;
export const KEYBOARD_STEP_PX = 24;
export const DEFAULT_PANE_SIZES = [0.82, 1.3, 0.88];
export const PANE_SIZE_STORAGE_KEY = 'tea121.workbench.pane-sizes';

export const clampValue = (value: number, min: number, max: number) => Math.min(Math.max(value, min), max);

/** One flexible track per pane, with a fixed track for every splitter in between. */
export const paneGridTemplate = (sizes: readonly number[], splitterWidth = SPLITTER_WIDTH) =>
  sizes.map(size => `minmax(0, ${size}fr)`).join(` ${splitterWidth}px `);

/** How many pixels one `fr` unit covers once the splitters have taken their space. */
export const frPerPixel = (gridWidth: number, totalFr: number, splitterCount: number, splitterWidth = SPLITTER_WIDTH) => {
  const free = gridWidth - splitterCount * splitterWidth;
  if (!(free > 0) || !(totalFr > 0)) return 0;
  return free / totalFr;
};

/**
 * Move a splitter by `deltaFr`, transferring space between the two panes it
 * separates. Their combined size is preserved and the third pane is untouched.
 */
export const resizePair = (sizes: readonly number[], index: number, deltaFr: number, minFr: number): number[] => {
  const next = [...sizes];
  if (index < 0 || index + 1 >= sizes.length) return next;
  const pair = sizes[index] + sizes[index + 1];
  if (!(pair > 0) || pair < minFr * 2) return next;
  const target = clampValue(sizes[index] + deltaFr, minFr, pair - minFr);
  next[index] = target;
  next[index + 1] = pair - target;
  return next;
};

/** Validate a value read back from storage before trusting it. */
export const normalizePaneSizes = (value: unknown, count: number): number[] | null => {
  if (!Array.isArray(value) || value.length !== count) return null;
  const sizes = value.map(item => (typeof item === 'number' ? item : Number.NaN));
  return sizes.every(size => Number.isFinite(size) && size > 0) ? sizes : null;
};
