// API base URL.
// - Production build with VITE_API_URL unset: '' (same origin, works behind any hostname or reverse proxy).
// - `npm run dev` (Vite on :5173) with VITE_API_URL unset: http://localhost:5000.
// - VITE_API_URL set: used as-is (use this if the API lives on a different origin).
export const API_URL = import.meta.env.VITE_API_URL ?? (import.meta.env.DEV ? 'http://localhost:5000' : '');
