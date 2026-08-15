# Brand assets

The mark is a claim descending into a line that **holds** it, above ground. It reads as
the electrical earth symbol at a glance — grounded in fact — and the cradle is the half
that symbol cannot say: held until proven, then released.

## Vector (source of truth)

| file | use |
|---|---|
| `logo-mark.svg` | the mark on its dark tile — app icons, avatars, anywhere ≥32px |
| `logo-mark-small.svg` | fewer elements, tighter bounds; the only one legible at 16px |
| `logo-mark-plain.svg` | no tile, `currentColor` — inherits the surrounding text colour |
| `logo-lockup.svg` | mark + wordmark, horizontal |
| `og-card.svg` | the link preview card |
| `avatar.svg` | full-bleed square for an org/profile avatar — the mark sits inside a safe area so a circular crop does not clip it |

## Raster (`raster/`, generated)

`avatar-{512,1024}.png` — what to upload as a GitHub organisation or profile picture
(GitHub applies its own rounding, so the source is square and full-bleed).

`mark-{16,32,48,64,128,180,192,256,512,1024}.png` — 16/32/48 render from the small
variant, the rest from the full one. `lockup-1360.png`, `mark-plain-512.png` (RGBA,
transparent), `favicon.ico` (16/32/48 in one file).

Regenerate from the SVGs rather than editing a PNG; the vectors are the source.

## Console

`logo.txt` carries the terminal forms — unicode, an ascii-only fallback for terminals
that mangle box drawing, and an inline `┗┛ groundhold`.

## Rules

Do not recolour the cradle: the green is the same green a `satisfied` verdict prints,
and that correspondence is the point. On a light background use `logo-mark-plain.svg`
rather than the dark tile. Leave clear space of one bar-height on every side.
