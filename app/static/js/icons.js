// Small stroke icon set (24px grid, 1.8 stroke). Drawn for this project.
const P = {
  home: "M3 10.5 12 3l9 7.5V21h-6v-6H9v6H3z",
  docs: "M7 3h7l5 5v13H7zM14 3v5h5M10 13h6M10 17h6",
  upload: "M12 16V4M7 9l5-5 5 5M4 16v4h16v-4",
  shield: "M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6zM9 12l2 2 4-4",
  trash: "M4 7h16M9 7V4h6v3M6 7l1 14h10l1-14",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21c0-4 4-6 8-6s8 2 8 6",
  admin: "M4 21V10M10 21V4M16 21v-7M22 21H2",
  search: "M11 18a7 7 0 1 0 0-14 7 7 0 0 0 0 14zM21 21l-4.5-4.5",
  bell: "M6 16V11a6 6 0 1 1 12 0v5l2 2H4zM10 21h4",
  sun: "M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10zM12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4",
  moon: "M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z",
  menu: "M4 6h16M4 12h16M4 18h16",
  x: "M6 6l12 12M18 6 6 18",
  check: "M5 12.5 10 17 19 7",
  download: "M12 4v12M7 11l5 5 5-5M4 20h16",
  share: "M16 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM8 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM16 22a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM10.6 13.5l2.8 1.8M13.4 6.7l-2.8 1.8",
  lock: "M6 11h12v10H6zM8 11V7a4 4 0 1 1 8 0v4",
  key: "M15 9a4 4 0 1 0-3.9 4.9L4 21v-3h3v-3h3l1.1-1.1",
  clock: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM12 7v5l3 2",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  ban: "M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18zM5.6 5.6l12.8 12.8",
  link: "M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1",
  arrow: "M5 12h14M13 6l6 6-6 6",
  tag: "M3 12V4h8l10 10-8 8zM7.5 8.5h.01",
  edit: "M4 20h4L19 9l-4-4L4 16zM14 6l4 4",
  history: "M3 12a9 9 0 1 0 3-6.7M3 4v5h5M12 8v4l3 2",
  grid: "M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z",
  list: "M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h11",
  alert: "M12 3 2 20h20zM12 10v4M12 17h.01",
  restore: "M3 12a9 9 0 1 0 3-6.7M3 4v5h5",
  hold: "M12 3v18M5 7h14l-3 6h-8zM8 21h8",
  device: "M4 5h16v11H4zM2 19h20",
  file: "M7 3h7l5 5v13H7zM14 3v5h5",
  sparkle: "M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5 18 18M6 18l2.5-2.5M15.5 8.5 18 6",
  people: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21c0-4 3-6 7-6s7 2 7 6M16 3.5a4 4 0 0 1 0 7M18 15c2.5.5 4 2.5 4 6",
  chain: "M9 15 15 9M7.5 12.5l-2 2a3.5 3.5 0 0 0 5 5l2-2M16.5 11.5l2-2a3.5 3.5 0 0 0-5-5l-2 2",
  export: "M12 3v12M7 8l5-5 5 5M5 14v6h14v-6",
  verify: "M12 3 4 6v6c0 5 3.5 8 8 9 4.5-1 8-4 8-9V6zM9 12l2 2 4-4",
};

export function icon(name, cls) {
  const NS = "http://www.w3.org/2000/svg";
  const s = document.createElementNS(NS, "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.8");
  s.setAttribute("stroke-linecap", "round");
  s.setAttribute("stroke-linejoin", "round");
  s.setAttribute("aria-hidden", "true");
  if (cls) s.setAttribute("class", cls);
  const p = document.createElementNS(NS, "path");
  p.setAttribute("d", P[name] || P.file);
  s.append(p);
  return s;
}
