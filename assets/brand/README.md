# Graphite Brand Assets

- `graphite-logo.png` — master logo, transparent background, 754×754.
- `graphite-logo-256.png` — 256×256, used in the root `README.md`.
- `graphite-logo-128.png` — 128×128, for smaller embeds (badges pages, wikis).
- `graphite-logo-16.png` — 16×16 flat icon, used for `favicon-16.png` in the dashboard.

Favicons generated from the same master are under `dashboard/public/` (`favicon.ico`,
`favicon-32.png`, `favicon-16.png`) and wired into `dashboard/index.html`.

Do not regenerate from a re-compressed or re-exported copy — always derive new sizes
from `graphite-logo.png` to avoid compounding artifacts.
