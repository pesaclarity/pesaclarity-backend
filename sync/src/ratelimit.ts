// A token bucket per key, kept in memory. A cell lives on one node at a
// time, so per-cell limits hold; a restart refills the buckets, which is fine
// for abuse control.

export class RateLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();

  private readonly capacity: number;
  private readonly perMinute: number;
  private readonly maxKeys: number;

  constructor(capacity: number, perMinute: number, maxKeys = 10_000) {
    this.capacity = capacity;
    this.perMinute = perMinute;
    this.maxKeys = maxKeys;
  }

  take(key: string, now: number, cost = 1): boolean {
    let b = this.buckets.get(key);
    if (!b) {
      if (this.buckets.size >= this.maxKeys) this.buckets.clear();
      b = { tokens: this.capacity, at: now };
      this.buckets.set(key, b);
    }
    b.tokens = Math.min(this.capacity, b.tokens + ((now - b.at) * this.perMinute) / 60_000);
    b.at = now;
    if (b.tokens < cost) return false;
    b.tokens -= cost;
    return true;
  }
}
