/** Full-page navigation that replaces the current history entry. Its own module so tests can stub it. */
export function replaceLocation(url: string): void {
  window.location.replace(url);
}
