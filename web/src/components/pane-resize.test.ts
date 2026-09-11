import { describe, expect, it } from 'vitest';
import { DEFAULT_PANE_SIZES, frPerPixel, normalizePaneSizes, paneGridTemplate, resizePair } from './pane-resize';

describe('paneGridTemplate', () => {
  it('gives every pane a flexible track and every splitter a fixed one', () => {
    expect(paneGridTemplate([1, 1, 1], 6)).toBe('minmax(0, 1fr) 6px minmax(0, 1fr) 6px minmax(0, 1fr)');
  });

  it('defaults to the shipped three column ratio', () => {
    expect(DEFAULT_PANE_SIZES).toEqual([0.82, 1.3, 0.88]);
  });
});

describe('frPerPixel', () => {
  it('measures one fr unit inside the space left over by the splitters', () => {
    expect(frPerPixel(1012, 3, 2, 6)).toBeCloseTo(1000 / 3, 10);
  });

  it('returns 0 when the grid has no usable width', () => {
    expect(frPerPixel(12, 3, 2, 6)).toBe(0);
    expect(frPerPixel(0, 0, 2, 6)).toBe(0);
  });
});

describe('resizePair', () => {
  it('transfers space between the two panes sharing a splitter', () => {
    expect(resizePair([1, 1, 1], 0, 0.5, 0.1)).toEqual([1.5, 0.5, 1]);
    expect(resizePair([1, 1, 1], 1, -0.25, 0.1)).toEqual([1, 0.75, 1.25]);
  });

  it('clamps so neither neighbour collapses below the minimum', () => {
    expect(resizePair([1, 1, 1], 0, 5, 0.25)).toEqual([1.75, 0.25, 1]);
    expect(resizePair([1, 1, 1], 0, -5, 0.25)).toEqual([0.25, 1.75, 1]);
  });

  it('ignores drags that cannot satisfy the minimum on both sides', () => {
    expect(resizePair([0.2, 0.2, 1], 0, 1, 0.25)).toEqual([0.2, 0.2, 1]);
  });

  it('ignores out of range splitter indexes', () => {
    expect(resizePair([1, 1, 1], 2, 1, 0.1)).toEqual([1, 1, 1]);
  });
});

describe('normalizePaneSizes', () => {
  it('accepts a stored ratio with the expected length', () => {
    expect(normalizePaneSizes([0.82, 1.3, 0.88], 3)).toEqual([0.82, 1.3, 0.88]);
  });

  it('rejects malformed, stale or non positive values', () => {
    expect(normalizePaneSizes(null, 3)).toBeNull();
    expect(normalizePaneSizes([1, 1], 3)).toBeNull();
    expect(normalizePaneSizes([1, 1, 0], 3)).toBeNull();
    expect(normalizePaneSizes([1, 1, 'x'], 3)).toBeNull();
    expect(normalizePaneSizes('nope', 3)).toBeNull();
  });
});
