import { domainContract } from './contracts/domain.js';
import { harness } from './helpers.js';

domainContract('SQLite domain contract', async (t) => {
  const h = harness();
  t.after(h.close);
  return {
    framework: h.framework,
    people: h.people,
    setTime: (value) => h.setTime(new Date(value).toISOString()),
  };
});
