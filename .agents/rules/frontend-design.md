# Front-End Design Standards: Clean, Minimalist SaaS MVP

## Discarded Rules & Architectural Pivot
- **Discard all brutalist, cyberpunk, and neo-brutalist design rules.**
- **Remove all decorative "hacker" text, brackets ([ ]), crosshairs (+), and fake terminal comments (such as // REV_04 or SYNC_BLOCK).**
- **Remove asymmetrical left-hand margin columns, marginalia gutters, and spine lines.**

---

## 1. Layout & Architecture
- **Full Width Centered Container**: Utilize screen space on desktop monitors using a generous container (`width: 95%; max-width: 1600px; margin: 0 auto;`).
- **Responsive Tables**: Wrap tables in a container with `overflow-x: auto` so no data or action buttons are clipped. Ensure table columns have adequate minimum widths.
- **Spread Grids & Components**: Spread stat cards evenly using CSS Grid (`grid-template-columns: repeat(3, 1fr)`) or Flexbox. Full-width input fields that match the expanded screen real estate.
- **Responsive**: Clean mobile stacking without hiding essential columns or breaking layout.

---

## 2. Typography
- **Primary Font**: Use standard, clean modern web sans-serif fonts such as 'Inter' or 'Roboto' for all UI text, headers, navigation, labels, tables, and buttons.
- **Code / Evidence Snippets**: Monospace is reserved strictly for raw technical evidence or code snippets (`ui-monospace`, `Consolas`, `Monaco`).
- **Weights & Hierarchy**: Normal 400 for body, Medium 500 for secondary headers/labels, Semibold 600 for titles. Standard tracking and line heights.

---

## 3. Visual Styling & Dark Mode Palette
- **Palette**: Simple, professional dark mode (Zinc / Slate neutrals):
  - Base background: `#09090b`
  - Elevated surfaces & cards: `#121316` / `#18181b`
  - Subtle borders: `1px solid #27272a`
  - High-readability text: `#f4f4f5` (primary), `#a1a1aa` (secondary), `#71717a` (muted)
  - Primary accent: Clean indigo/blue (`#4f46e5`, hover: `#4338ca`)
- **Corners & Borders**:
  - Subtle rounded corners (`border-radius: 6px` to `10px`).
  - Standard, crisp 1px borders without clipped/angled corners (`clip-path`) or extreme contrast.
- **Form Controls & Inputs**:
  - Clear, legible inputs with standard padding, clean placeholders, and soft focus rings (`box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2)`).
  - Clear, professional buttons with soft hover transitions.
