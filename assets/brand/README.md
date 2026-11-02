# Graphite Brand Assets

- `graphite-logo.png` — master logo, transparent background, 754×754.
- `graphite-logo-256.png` — 256×256, used in the root `README.md`; the console's header logo
  (`dashboard/public/graphite-logo.png`) is a byte-identical copy.
- `graphite-logo-128.png` — 128×128, for smaller embeds (badges pages, wikis).
- `graphite-logo-16.png` — a flat, simplified variant of the logo for the smallest sizes,
  1024×1024 despite its name.

Favicons are under `dashboard/public/` (`favicon.ico` with 16, 32 and 48 px images,
`favicon-16.png`, `favicon-32.png`, `favicon-48.png`, and a 180×180 `apple-touch-icon.png`)
and wired into `dashboard/index.html`.

Do not regenerate from a re-compressed or re-exported copy — always derive new sizes
from `graphite-logo.png` to avoid compounding artifacts.
