// Counts requests in kv and denies once the count passes config.max
// (default 1). Logs each count, so tests can check the filter log.
import { defineFilter, deny, kv } from "bouncer";

interface Config {
  max?: number;
}

export default defineFilter<Config>({
  async onRequest(req, next, ctx) {
    const n = kv.incr("n");
    console.log(`request ${n}`);
    const max = ctx.config.max ?? 1;
    return n > max ? deny(`over ${max}`) : next(req);
  },
});
