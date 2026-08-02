/* RECONKIT bridge — SVG starships (browser-safe, no ASCII dependency)
 *
 * Terminal still uses pure ASCII from shell/fleet_art.py.
 * Dashboard uses scalable SVG silhouettes so hulls stay sharp at any size.
 */

/** Module → hull silhouette key */
const MODULE_HULL = {
  subdomains: "constitution",
  dns: "excelsior",
  httpprobe: "nova",
  tls: "miranda",
  crawl: "ambassador",
  js: "galaxy",
  params: "constitution_a",
  content: "enterprise",
  xss: "bop",
  sqli: "klingon",
  ssrf_ssti: "romulan",
  nuclei: "ferengi",
  cloud: "pathfinder",
  screenshots: "viewscreen",
  pipeline: "flag",
  default: "constitution",
};

/** Class name → hull (fallback when module id missing) */
const CLASS_HULL = {
  Constitution: "constitution",
  "Constitution Refit": "constitution_a",
  "Constitution-A": "pathfinder",
  Excelsior: "excelsior",
  Nova: "nova",
  Miranda: "miranda",
  Ambassador: "ambassador",
  Galaxy: "galaxy",
  "Bird of Prey": "bop",
  "Klingon Warship": "klingon",
  "Romulan Warbird": "romulan",
  "Ferengi Marauder": "ferengi",
  "NCC-1701-A": "viewscreen",
  Flag: "flag",
};

/**
 * SVG body fragments (viewBox 0 0 160 64 unless noted).
 * Each hull is a distinct silhouette.
 */
const HULL_PATHS = {
  // Classic Constitution — saucer + neck + secondary + twin nacelles
  constitution: `
    <ellipse cx="58" cy="22" rx="36" ry="14" />
    <ellipse cx="58" cy="22" rx="10" ry="6" opacity="0.35" fill="#050810" />
    <path d="M70 30 L78 42 L92 46 L92 40 L76 34 Z" />
    <ellipse cx="100" cy="48" rx="22" ry="7" />
    <rect x="88" y="40" width="6" height="10" rx="1" />
    <ellipse cx="118" cy="36" rx="18" ry="4.5" transform="rotate(-8 118 36)" />
    <ellipse cx="118" cy="56" rx="18" ry="4.5" transform="rotate(8 118 56)" />
    <path d="M100 44 L118 36 M100 50 L118 56" stroke-width="1.5" fill="none" />
  `,
  constitution_a: `
    <ellipse cx="56" cy="24" rx="34" ry="13" />
    <ellipse cx="56" cy="24" rx="9" ry="5" opacity="0.35" fill="#050810" />
    <path d="M68 32 L80 44 L100 48 L100 42 L78 36 Z" />
    <ellipse cx="108" cy="48" rx="26" ry="7" />
    <ellipse cx="128" cy="34" rx="16" ry="4" transform="rotate(-10 128 34)" />
    <ellipse cx="128" cy="58" rx="16" ry="4" transform="rotate(10 128 58)" />
    <path d="M108 44 L128 34 M108 52 L128 58" stroke-width="1.5" fill="none" />
    <rect x="40" y="18" width="8" height="3" rx="1" opacity="0.8" />
  `,
  // Excelsior — longer neck / bulkier secondary
  excelsior: `
    <ellipse cx="48" cy="22" rx="32" ry="12" />
    <ellipse cx="48" cy="22" rx="8" ry="5" opacity="0.35" fill="#050810" />
    <path d="M62 28 L90 40 L90 48 L70 44 Z" />
    <ellipse cx="110" cy="46" rx="34" ry="8" />
    <ellipse cx="138" cy="32" rx="14" ry="3.5" />
    <ellipse cx="138" cy="58" rx="14" ry="3.5" />
    <path d="M120 42 L138 32 M120 50 L138 58" stroke-width="1.5" fill="none" />
    <rect x="100" y="40" width="16" height="4" rx="1" opacity="0.5" />
  `,
  // Nova — compact scout
  nova: `
    <ellipse cx="70" cy="30" rx="28" ry="11" />
    <ellipse cx="70" cy="30" rx="7" ry="4" opacity="0.35" fill="#050810" />
    <path d="M88 34 L110 40 L110 46 L92 42 Z" />
    <ellipse cx="118" cy="44" rx="16" ry="5" />
    <ellipse cx="128" cy="36" rx="10" ry="3" />
    <ellipse cx="128" cy="52" rx="10" ry="3" />
  `,
  // Miranda / Reliant — roll bar
  miranda: `
    <ellipse cx="70" cy="32" rx="30" ry="12" />
    <ellipse cx="70" cy="32" rx="8" ry="5" opacity="0.35" fill="#050810" />
    <path d="M48 20 L48 12 L92 12 L92 20" stroke-width="2.5" fill="none" />
    <rect x="66" y="12" width="8" height="10" rx="1" />
    <ellipse cx="110" cy="40" rx="18" ry="5" />
    <path d="M92 34 L110 38" stroke-width="2" fill="none" />
  `,
  // Ambassador
  ambassador: `
    <ellipse cx="52" cy="22" rx="30" ry="12" />
    <path d="M66 30 L86 42 L104 46 L104 40 L78 34 Z" />
    <ellipse cx="112" cy="48" rx="28" ry="7" />
    <ellipse cx="132" cy="34" rx="15" ry="3.5" transform="rotate(-6 132 34)" />
    <ellipse cx="132" cy="58" rx="15" ry="3.5" transform="rotate(6 132 58)" />
    <path d="M112 44 L132 34 M112 52 L132 58" stroke-width="1.5" fill="none" />
  `,
  // Galaxy — large saucer
  galaxy: `
    <ellipse cx="54" cy="24" rx="40" ry="16" />
    <ellipse cx="54" cy="24" rx="12" ry="7" opacity="0.35" fill="#050810" />
    <path d="M72 34 L88 48 L108 52 L108 46 L84 40 Z" />
    <ellipse cx="116" cy="50" rx="28" ry="8" />
    <ellipse cx="138" cy="36" rx="16" ry="4" transform="rotate(-12 138 36)" />
    <ellipse cx="138" cy="60" rx="16" ry="4" transform="rotate(12 138 60)" />
    <path d="M116 46 L138 36 M116 54 L138 60" stroke-width="1.8" fill="none" />
    <circle cx="54" cy="24" r="3" opacity="0.9" />
  `,
  enterprise: `
    <ellipse cx="58" cy="22" rx="36" ry="14" />
    <path d="M70 30 L78 42 L92 46 L92 40 L76 34 Z" />
    <ellipse cx="100" cy="48" rx="22" ry="7" />
    <ellipse cx="118" cy="36" rx="18" ry="4.5" transform="rotate(-8 118 36)" />
    <ellipse cx="118" cy="56" rx="18" ry="4.5" transform="rotate(8 118 56)" />
    <path d="M100 44 L118 36 M100 50 L118 56" stroke-width="1.5" fill="none" />
    <text x="20" y="60" font-size="7" font-family="monospace" fill="currentColor" opacity="0.7">NCC-1701</text>
  `,
  // Klingon Bird of Prey — wings down
  bop: `
    <path d="M80 28 L100 32 L100 40 L80 44 L70 36 Z" />
    <ellipse cx="72" cy="36" rx="10" ry="8" />
    <path d="M80 32 L30 12 L34 20 L80 36 Z" />
    <path d="M80 40 L30 56 L34 48 L80 40 Z" />
    <path d="M100 34 L140 28 L140 36 L100 38 Z" />
    <path d="M100 38 L140 44 L140 36" />
    <circle cx="72" cy="36" r="3" opacity="0.5" fill="#050810" />
  `,
  // Klingon warship — bulkier angular
  klingon: `
    <path d="M40 32 L70 20 L110 24 L130 32 L110 44 L70 48 Z" />
    <path d="M70 20 L50 8 L60 18" />
    <path d="M70 48 L50 58 L60 46" />
    <path d="M110 24 L150 16 L150 28 L120 30 Z" />
    <path d="M110 40 L150 48 L150 36 L120 38 Z" />
    <circle cx="78" cy="34" r="5" opacity="0.4" fill="#050810" />
    <rect x="88" y="30" width="14" height="8" rx="1" opacity="0.5" />
  `,
  // Romulan Warbird — winged bird
  romulan: `
    <ellipse cx="90" cy="34" rx="18" ry="10" />
    <path d="M72 30 L20 10 L28 22 L74 34 Z" />
    <path d="M72 38 L20 54 L28 46 L74 38 Z" />
    <path d="M108 30 L150 18 L150 30 L112 34 Z" />
    <path d="M108 38 L150 50 L150 38 L112 38 Z" />
    <path d="M80 34 L100 34" stroke-width="2" fill="none" opacity="0.6" />
    <circle cx="90" cy="34" r="4" opacity="0.4" fill="#050810" />
  `,
  // Ferengi Marauder — curved / claw
  ferengi: `
    <path d="M40 36 Q70 10 110 20 Q140 28 145 40 Q140 52 110 48 Q70 58 40 36 Z" />
    <ellipse cx="95" cy="34" rx="16" ry="9" opacity="0.35" fill="#050810" />
    <path d="M50 28 L30 16 L36 28" />
    <path d="M50 44 L30 54 L36 42" />
    <circle cx="100" cy="34" r="4" opacity="0.6" />
  `,
  pathfinder: `
    <ellipse cx="60" cy="28" rx="28" ry="11" />
    <path d="M78 34 L100 42 L118 44 L118 40 L96 36 Z" />
    <ellipse cx="120" cy="44" rx="14" ry="5" />
    <ellipse cx="128" cy="36" rx="9" ry="2.5" />
    <ellipse cx="128" cy="50" rx="9" ry="2.5" />
    <circle cx="48" cy="28" r="3" opacity="0.7" />
  `,
  viewscreen: `
    <rect x="30" y="16" width="100" height="36" rx="4" fill="none" stroke-width="2.5" />
    <rect x="38" y="22" width="84" height="24" rx="2" opacity="0.25" />
    <ellipse cx="80" cy="34" rx="14" ry="6" opacity="0.5" />
    <path d="M50 34 L70 34 M90 34 L110 34" stroke-width="1.5" fill="none" opacity="0.6" />
  `,
  flag: `
    <ellipse cx="80" cy="32" rx="36" ry="14" />
    <path d="M80 18 L80 8 M72 12 L88 12" stroke-width="2" fill="none" />
    <ellipse cx="80" cy="32" rx="8" ry="5" opacity="0.4" fill="#050810" />
  `,
};

function resolveHull(moduleId, shipClass) {
  if (moduleId && MODULE_HULL[moduleId]) return MODULE_HULL[moduleId];
  if (shipClass && CLASS_HULL[shipClass]) return CLASS_HULL[shipClass];
  return "constitution";
}

/**
 * @param {object} opts
 * @param {string} [opts.module]
 * @param {string} [opts.class]
 * @param {string} [opts.hull]
 * @param {string} [opts.color]
 * @param {number} [opts.width]
 * @param {number} [opts.height]
 * @param {string} [opts.className]
 * @param {boolean} [opts.glow]
 * @param {boolean} [opts.animate]
 */
function svgShip(opts = {}) {
  const hull = opts.hull || resolveHull(opts.module, opts.class);
  const color = opts.color || "#5eead4";
  const w = opts.width || 160;
  const h = opts.height || 64;
  const body = HULL_PATHS[hull] || HULL_PATHS.constitution;
  const cls = ["ship-svg", opts.className || "", opts.animate ? "ship-svg-fly" : ""]
    .filter(Boolean)
    .join(" ");
  const glow = opts.glow
    ? `<filter id="sg-${hull}" x="-40%" y="-40%" width="180%" height="180%">
         <feDropShadow dx="0" dy="0" stdDeviation="2.5" flood-color="${color}" flood-opacity="0.65"/>
       </filter>`
    : "";
  const filterAttr = opts.glow ? `filter="url(#sg-${hull})"` : "";
  // unique filter ids when many ships on page
  const uid = `sg-${hull}-${Math.random().toString(36).slice(2, 7)}`;
  const glowUnique = opts.glow
    ? `<filter id="${uid}" x="-40%" y="-40%" width="180%" height="180%">
         <feDropShadow dx="0" dy="0" stdDeviation="2.5" flood-color="${color}" flood-opacity="0.65"/>
       </filter>`
    : "";
  const fAttr = opts.glow ? `filter="url(#${uid})"` : "";

  return `<svg class="${cls}" viewBox="0 0 160 64" width="${w}" height="${h}"
      xmlns="http://www.w3.org/2000/svg" role="img" aria-label="${hull} starship">
    <defs>${glowUnique}</defs>
    <g fill="${color}" stroke="${color}" stroke-width="1" ${fAttr}>
      ${body}
    </g>
  </svg>`;
}

/** Hero flagship — large Galaxy silhouette */
function svgFlagship(color = "#5eead4") {
  return `<svg class="hero-flagship ship-svg-fly" viewBox="0 0 320 120" width="100%" height="110"
      xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Flagship Enterprise">
    <defs>
      <linearGradient id="fg" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%" stop-color="${color}"/>
        <stop offset="100%" stop-color="#38bdf8"/>
      </linearGradient>
      <filter id="fg-glow" x="-20%" y="-20%" width="140%" height="140%">
        <feDropShadow dx="0" dy="0" stdDeviation="3" flood-color="${color}" flood-opacity="0.55"/>
      </filter>
    </defs>
    <g fill="url(#fg)" stroke="${color}" stroke-width="1.2" filter="url(#fg-glow)">
      <ellipse cx="110" cy="48" rx="72" ry="28"/>
      <ellipse cx="110" cy="48" rx="22" ry="12" fill="#050810" opacity="0.45"/>
      <path d="M150 62 L180 88 L220 96 L220 86 L170 72 Z"/>
      <ellipse cx="235" cy="92" rx="52" ry="14"/>
      <ellipse cx="280" cy="68" rx="32" ry="7" transform="rotate(-12 280 68)"/>
      <ellipse cx="280" cy="110" rx="32" ry="7" transform="rotate(12 280 110)"/>
      <path d="M235 86 L280 68 M235 98 L280 110" fill="none" stroke-width="2"/>
      <circle cx="110" cy="48" r="5" fill="#ffcc80"/>
    </g>
    <text x="16" y="112" fill="#ffcc80" font-family="Orbitron,sans-serif" font-size="11" letter-spacing="0.12em">
      U.S.S. ENTERPRISE  ·  FLAGSHIP
    </text>
  </svg>`;
}

/** Spacedock as SVG station with berths */
function svgSpacedock(color = "#99ccff") {
  return `<svg class="hero-dock" viewBox="0 0 280 160" width="100%" height="140"
      xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Earth Spacedock">
    <defs>
      <linearGradient id="dg2" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#f5a623"/>
        <stop offset="100%" stop-color="${color}"/>
      </linearGradient>
    </defs>
    <!-- outer ring -->
    <ellipse cx="140" cy="70" rx="120" ry="48" fill="none" stroke="url(#dg2)" stroke-width="3"/>
    <ellipse cx="140" cy="70" rx="100" ry="38" fill="none" stroke="${color}" stroke-width="1.2" opacity="0.5"/>
    <!-- hub -->
    <rect x="100" y="48" width="80" height="44" rx="6" fill="#0a1220" stroke="#f5a623" stroke-width="2"/>
    <text x="140" y="68" text-anchor="middle" fill="#ffcc80" font-family="Share Tech Mono,monospace" font-size="8">SPACEDOCK</text>
    <text x="140" y="80" text-anchor="middle" fill="${color}" font-family="Share Tech Mono,monospace" font-size="7">CORE RING</text>
    <!-- berths -->
    ${[0, 1, 2, 3].map((i) => {
      const x = 40 + i * 55;
      return `
        <g transform="translate(${x}, 105)">
          <rect x="0" y="0" width="42" height="28" rx="3" fill="#0a1220" stroke="${color}" stroke-width="1.5"/>
          <text x="21" y="12" text-anchor="middle" fill="#f5a623" font-size="6" font-family="monospace">BAY-${i + 1}</text>
          <ellipse cx="21" cy="20" rx="12" ry="4" fill="${color}" opacity="0.85"/>
          <line x1="21" y1="0" x2="21" y2="-12" stroke="${color}" stroke-width="1" opacity="0.6"/>
        </g>`;
    }).join("")}
    <!-- pylons -->
    <line x1="140" y1="92" x2="140" y2="105" stroke="#f5a623" stroke-width="2"/>
    <line x1="60" y1="90" x2="50" y2="105" stroke="${color}" stroke-width="1.5" opacity="0.7"/>
    <line x1="220" y1="90" x2="230" y2="105" stroke="${color}" stroke-width="1.5" opacity="0.7"/>
    <!-- docking ships at bays (tiny) -->
    <ellipse cx="61" cy="125" rx="8" ry="3" fill="#5eead4" class="dock-ship"/>
    <ellipse cx="116" cy="125" rx="8" ry="3" fill="#38bdf8" class="dock-ship"/>
    <ellipse cx="171" cy="125" rx="8" ry="3" fill="#f472b6" class="dock-ship"/>
    <ellipse cx="226" cy="125" rx="8" ry="3" fill="#fbbf24" class="dock-ship"/>
  </svg>`;
}

/** RECONKIT title as SVG text (not STAR TREK) */
function svgReconkitWordmark() {
  return `<svg class="hero-wordmark" viewBox="0 0 280 40" width="100%" height="36"
      xmlns="http://www.w3.org/2000/svg" role="img" aria-label="RECONKIT">
    <text x="140" y="28" text-anchor="middle"
      font-family="Orbitron, Inter, sans-serif"
      font-size="22" font-weight="700" letter-spacing="0.18em"
      fill="#f5a623"
      style="filter: drop-shadow(0 0 6px rgba(245,166,35,0.5))">RECONKIT</text>
  </svg>`;
}

// Export for app.js (browser global)
window.ReconShips = {
  MODULE_HULL,
  resolveHull,
  svgShip,
  svgFlagship,
  svgSpacedock,
  svgReconkitWordmark,
};
