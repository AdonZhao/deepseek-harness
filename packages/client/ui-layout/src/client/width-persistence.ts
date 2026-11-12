/**
 * The two panel widths a drag leaves behind. Every other layout fact in the
 * frame — expansion, presentation, the measured viewport — is transient; those
 * are either reported by an occupant or remeasured at mount, so restoring them
 * from storage would resurrect stale chrome.
 *
 * Why not `defineStore({ persist })`: that hook persists the whole state, this
 * store's derived chrome (`rightbarShown`, `rightbarTrack`,
 * `rightbarFullscreen`, `viewportWidth`) included, which is exactly what must
 * not survive a reload. A width preference is also a single number per panel, so
 * two scalar entries carry it without hydrating anything else. A reset gesture
 * must therefore remove these keys itself: `clearPersisted()` on the store
 * deletes nothing while no `persist` key is declared.
 */
import { clampWidth } from './columns.ts'

/** Storage key of the dragged sidebar width, in px. */
export const SIDEBAR_WIDTH_KEY = 'dsh.layout.sidebar-width.v1'

/** Storage key of the dragged right panel width, in px. */
export const RIGHTBAR_WIDTH_KEY = 'dsh.layout.rightbar-width.v1'

/**
 * Resolve the storage object, or undefined where it is absent or refused.
 *
 * Reading `localStorage` itself throws where the browser blocks site data
 * (`SecurityError`) or in a sandboxed frame without `allow-same-origin`, so the
 * lookup sits inside the same guard as its use: a blocked store costs the
 * preference, never the frame.
 * @returns the storage object, or undefined without one.
 */
function storage(): Storage | undefined {
  try { return localStorage } catch (_storageUnavailable) { return undefined }
}

/**
 * Read one remembered width.
 *
 * A missing, unreadable, or non-positive entry means no preference: the caller
 * supplies its own default, so a corrupt entry costs a default width rather
 * than a broken frame.
 * @param key - storage key of the panel.
 * @param min - drag floor of the panel.
 * @param max - drag ceiling of the panel; the right panel passes Infinity
 *   because its ceiling follows the frame width solved at render time.
 * @returns the remembered width in px, or undefined without one.
 */
export function readPanelWidth(key: string, min: number, max: number): number | undefined {
  const store = storage()
  if (store === undefined) return undefined
  let raw: string | null
  try { raw = store.getItem(key) } catch (_storageUnavailable) { return undefined }
  if (raw === null) return undefined
  const px = Number(raw)
  return Number.isFinite(px) && px > 0 ? clampWidth(px, min, max) : undefined
}

/**
 * Remember one width after a drag applied it.
 *
 * Storage failures (quota, private mode, disabled storage) only drop the
 * preference; the drag already reached the live layout and stays there for the
 * life of the page.
 * @param key - storage key of the panel.
 * @param px - applied width in px.
 */
export function writePanelWidth(key: string, px: number): void {
  const store = storage()
  if (store === undefined) return
  try { store.setItem(key, `${px}`) }
  catch (error) { console.error('Panel width persistence failed:', error) }
}
