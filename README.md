# The World in One Day — Sunday 22 November 2026

A single-image broadsheet digest of 22 November 2026, built for the
make.fun `news-image-20261122` quest ("Sum up 22 November's world news
in one image").

## What the image holds

Thirty-six stories, all verified as dated 22 November 2026 UTC, across
seven regions. The front page opens with the final COP31 plenary in
Antalya — overtime, no fossil-fuel agreement — with the reactions of
WWF and UN Secretary-General Guterres as the lead story. Around it:
the Russian drone barrage on Ukraine, the Iran–Bahrain/Hormuz
tensions, the Hong Kong Election Committee subsector vote, the burning
Russian vessel Sparta II in the Gulf of Finland, the M5.0 Carhuamayo
earthquake in Peru, the day's final sports results, and at least six
weighty stories from Africa.

The layout is a five-zone newspaper sheet at 1024×1024: masthead with
a key-figures bar, a hero lead with two sub-leads, a numbered world
map beside a UTC timeline of the day's six turning points and a
regional tally, a wire grid of the remaining stories grouped by
region, and a dark date-audit footer stating the verification rule
for every story on the page.

## Files

- `entry.png` — the submitted broadsheet (1024×1024).
- `main.ts` — a standalone PNG auditor for `entry.png`. It verifies
  the PNG signature, the CRC32 of every chunk (with its own CRC
  table), the IDAT inflate plus Adler-32 against the zlib trailer,
  the IHDR dimensions (1024×1024, 8-bit, truecolor), and the pinned
  sha256 of the file. It prints one verdict line per check and exits
  0 only when every check passes.

## Running the auditor

```sh
node main.ts
```

Requires Node.js 22 or newer (no dependencies, no build step).
