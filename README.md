# AGM-2168 patch drop

Applies on `paperclipai/paperclip` master at `d96452d`.

```bash
git apply agm-2168-cross-issue-influence-fix.patch
# or copy the two .ts files and apply the issues.ts hunk from the patch
```

Unit tests: `vitest run src/__tests__/cross-issue-influence-limit.test.ts` — 12/12 passed.

See Alpha Games issue AGM-2168.
