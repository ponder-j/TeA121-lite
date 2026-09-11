import { Children, Fragment, useEffect, useRef, useState, type KeyboardEvent, type PointerEvent as ReactPointerEvent, type ReactNode } from 'react';
import { DEFAULT_PANE_SIZES, KEYBOARD_STEP_PX, MIN_PANE_WIDTH, PANE_SIZE_STORAGE_KEY, frPerPixel, normalizePaneSizes, paneGridTemplate, resizePair } from './pane-resize';

const WIDE_LAYOUT_QUERY = '(min-width: 1051px)';

const readStoredSizes = (key: string, count: number): number[] | null => {
  try {
    const raw = window.localStorage.getItem(key);
    return raw ? normalizePaneSizes(JSON.parse(raw), count) : null;
  } catch {
    return null;
  }
};

type DragState = { index: number; startX: number; startSizes: number[]; pxPerFr: number; pointerId: number };

type ResizablePanesProps = {
  children: ReactNode;
  className?: string;
  /** Where the column ratios are remembered between visits. */
  storageKey?: string;
  defaultSizes?: readonly number[];
  minPaneWidth?: number;
};

/**
 * Lays its children out in a grid, inserting a draggable splitter between each
 * pair of panes. Column ratios live in `fr` units, so panes keep their relative
 * proportions when the window is resized.
 *
 * Below 1051px the app switches to its own narrow layouts, so the splitters are
 * not rendered and the stylesheet keeps full control.
 */
export function ResizablePanes({ children, className = '', storageKey = PANE_SIZE_STORAGE_KEY, defaultSizes = DEFAULT_PANE_SIZES, minPaneWidth = MIN_PANE_WIDTH }: ResizablePanesProps) {
  const panes = Children.toArray(children);
  const paneCount = panes.length;
  const gridRef = useRef<HTMLDivElement>(null);
  const dragRef = useRef<DragState | null>(null);
  const [sizes, setSizes] = useState<number[]>(() => readStoredSizes(storageKey, paneCount) ?? defaultSizes.slice(0, paneCount));
  const sizesRef = useRef(sizes);
  const [activeSplitter, setActiveSplitter] = useState<number | null>(null);
  const [wideLayout, setWideLayout] = useState(() => window.matchMedia(WIDE_LAYOUT_QUERY).matches);

  useEffect(() => {
    const query = window.matchMedia(WIDE_LAYOUT_QUERY);
    const sync = () => setWideLayout(query.matches);
    sync();
    query.addEventListener('change', sync);
    return () => query.removeEventListener('change', sync);
  }, []);

  useEffect(() => () => { document.body.classList.remove('is-resizing-panes'); }, []);

  const persist = (next: number[]) => {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify(next.map(size => +size.toFixed(4))));
    } catch {
      /* storage can be unavailable (private mode); resizing still works */
    }
  };

  // A drag ends without any further state change, so the final ratio has to be
  // written here instead of from an effect watching `sizes`.
  const applySizes = (next: number[], persistNow = true) => {
    sizesRef.current = next;
    setSizes(next);
    if (persistNow) persist(next);
  };

  const totalFr = sizes.reduce((sum, size) => sum + size, 0);
  const splittersEnabled = wideLayout && paneCount > 1 && sizes.length === paneCount;

  const measurePxPerFr = () => {
    const grid = gridRef.current;
    if (!grid) return 0;
    return frPerPixel(grid.clientWidth, sizesRef.current.reduce((sum, size) => sum + size, 0), paneCount - 1);
  };

  const startDrag = (index: number) => (event: ReactPointerEvent<HTMLDivElement>) => {
    const pxPerFr = measurePxPerFr();
    if (!pxPerFr) return;
    event.preventDefault();
    event.currentTarget.setPointerCapture(event.pointerId);
    dragRef.current = { index, startX: event.clientX, startSizes: sizesRef.current, pxPerFr, pointerId: event.pointerId };
    setActiveSplitter(index);
    document.body.classList.add('is-resizing-panes');
  };

  const moveDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    const deltaFr = (event.clientX - drag.startX) / drag.pxPerFr;
    applySizes(resizePair(drag.startSizes, drag.index, deltaFr, minPaneWidth / drag.pxPerFr), false);
  };

  const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    const drag = dragRef.current;
    if (!drag) return;
    dragRef.current = null;
    setActiveSplitter(null);
    document.body.classList.remove('is-resizing-panes');
    if (event.currentTarget.hasPointerCapture(drag.pointerId)) event.currentTarget.releasePointerCapture(drag.pointerId);
    persist(sizesRef.current);
  };

  const nudgeWithKeyboard = (index: number) => (event: KeyboardEvent<HTMLDivElement>) => {
    const direction = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0;
    if (!direction) return;
    const pxPerFr = measurePxPerFr();
    if (!pxPerFr) return;
    event.preventDefault();
    applySizes(resizePair(sizesRef.current, index, (direction * KEYBOARD_STEP_PX) / pxPerFr, minPaneWidth / pxPerFr));
  };

  const resetSizes = () => applySizes(defaultSizes.slice(0, paneCount));

  return (
    <div
      className={`workbench-grid${splittersEnabled ? ' has-splitters' : ''}${className ? ` ${className}` : ''}`}
      ref={gridRef}
      style={splittersEnabled ? { gridTemplateColumns: paneGridTemplate(sizes) } : undefined}
    >
      {panes.map((pane, index) => (
        <Fragment key={index}>
          {pane}
          {splittersEnabled && index < paneCount - 1 && (
            <div
              className={`pane-splitter${activeSplitter === index ? ' active' : ''}`}
              role="separator"
              aria-orientation="vertical"
              aria-label={`调整第 ${index + 1} 栏与第 ${index + 2} 栏的宽度`}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={Math.round((sizes[index] / totalFr) * 100)}
              title="拖动调整宽度，双击恢复默认"
              tabIndex={0}
              onPointerDown={startDrag(index)}
              onPointerMove={moveDrag}
              onPointerUp={endDrag}
              onPointerCancel={endDrag}
              onDoubleClick={resetSizes}
              onKeyDown={nudgeWithKeyboard(index)}
            />
          )}
        </Fragment>
      ))}
    </div>
  );
}
