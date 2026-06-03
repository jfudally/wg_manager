/**
 * PostCSS pipeline used by Next.js to compile Tailwind directives.
 *
 * Tailwind v4 moved the PostCSS plugin to its own package
 * (``@tailwindcss/postcss``) — the older ``tailwindcss`` plugin name
 * no longer resolves at build time. ``next dev`` works either way
 * (it uses Tailwind's runtime style injection), but ``next build``
 * fails without this change. The Docker image build (Phase 2f
 * cycle 1) is the path that surfaced this regression — pinning it
 * here keeps the build path honest.
 */
export default {
  plugins: {
    "@tailwindcss/postcss": {},
    autoprefixer: {},
  },
};
