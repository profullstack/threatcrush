import { closeSync, fstatSync, openSync, readSync, statSync } from 'node:fs';

/**
 * Reads what was appended to a log since the last poll, exactly once.
 *
 * The watchers used to start a new read stream on every poll and record the
 * new position only when that stream closed. When the daemon was busy (a slow
 * state database), a read outlived the poll interval and the next poll started
 * another from the same offset: the same lines were processed again and again,
 * each copy stored as a new event, which made the database slower still, and
 * every overlapping stream held a file descriptor (dev2: 3,259 on syslog,
 * 1,549 on rotated-away logs). Here a poll reads synchronously, bounded to the
 * bytes that are there now, in fixed chunks, and never overlaps itself.
 */
export class LogTail {
  private pos: number;
  private partial = '';
  private inode: number | undefined;

  /** Starts at the end of the file: history is not replayed. */
  constructor(readonly path: string, fromStart = false) {
    try {
      const st = statSync(path);
      this.pos = fromStart ? 0 : st.size;
      this.inode = st.ino;
    } catch {
      this.pos = 0;
    }
  }

  get position(): number {
    return this.pos;
  }

  /**
   * Hands each complete new line to onLine. A line still being written (no
   * newline yet) waits for the next poll. Rotation (a new inode, or a file
   * shorter than our position) restarts at the top of the new file.
   * At most maxBytes are read per poll, so a burst is spread over polls
   * instead of blocking the daemon.
   */
  poll(onLine: (line: string) => void, maxBytes = 4 << 20): number {
    let fd: number;
    try {
      fd = openSync(this.path, 'r');
    } catch {
      return 0;
    }
    try {
      const st = fstatSync(fd);
      if ((this.inode !== undefined && st.ino !== this.inode) || st.size < this.pos) {
        this.pos = 0;
        this.partial = '';
      }
      this.inode = st.ino;
      const end = Math.min(st.size, this.pos + maxBytes);
      if (end <= this.pos) return 0;
      const buf = Buffer.allocUnsafe(Math.min(end - this.pos, 1 << 20));
      let lines = 0;
      while (this.pos < end) {
        const want = Math.min(buf.length, end - this.pos);
        const n = readSync(fd, buf, 0, want, this.pos);
        if (n <= 0) break;
        this.pos += n;
        const text = this.partial + buf.toString('utf-8', 0, n);
        const parts = text.split('\n');
        this.partial = parts.pop() ?? '';
        for (const line of parts) {
          if (line.trim()) {
            lines++;
            onLine(line);
          }
        }
      }
      // A runaway "line" (binary junk, no newline) must not grow forever.
      if (this.partial.length > 1 << 20) this.partial = '';
      return lines;
    } finally {
      closeSync(fd);
    }
  }
}
