# ShieldTier V2 — Design Reference Templates

Generated via 21st.dev Magic MCP tools. **These are visual references only — no project files were modified.**

## Templates Generated

| # | File | Component | Status |
|---|------|-----------|--------|
| 1 | `01-mission-control-dashboard.tsx` | Dashboard (landing page) | Done |
| 2 | `02-network-har-capture-table.tsx` | NetworkPanel (HAR table) | Done |
| 3 | `03-mitre-attack-heatmap.tsx` | MITREPanel (ATT&CK grid) | Done |
| 4 | `04-phishing-score-card.tsx` | PhishingScoreCard (email) | Done |
| 5 | `05-login-screen.tsx` | LoginScreen (auth gate) | Done |
| 6 | Settings Page | SettingsPage | Builder returned (opaque) |
| 7 | Report Modal | ReportModal | Builder returned (opaque) |

## Refinements (Blocked — Anthropic high load)

| # | Component | Refinement Focus |
|---|-----------|------------------|
| 1 | LoginScreen | Brand gradient glow, password strength bar, glass morphism |
| 2 | TopBar | Proxy glow, chat badge animation, threat-reactive border |
| 3 | VerticalTabBar | Active tab glow, badge pop animation, section labels |

## Logos (Not found in 21st.dev)

Security vendor logos (VirusTotal, MITRE, Splunk, Elastic, CrowdStrike) are not in the 21st.dev library. Source SVGs from official brand resources.

## Inspiration Sources Collected

- Dark analytics dashboard (stat cards, sparklines, incident reports)
- Dark sidebar navigation (macOS source-list style)
- Dark premium login/auth (glass morphism, animated particles)
- Dark chat messaging panel (P2P, presence indicators)

## Design Constraints Applied

- **Dark-first**: base `#1c1c1e`, elevated `#2c2c2e`, panel `#252526`
- **Threat colors**: blue `#0a84ff`, orange `#ff9f0a`, red `#ff453a`
- **Semantic**: success `#30d158`, warning `#ffd60a`, purple `#bf5af2`
- **Typography**: Inter (UI), JetBrains Mono (data/hashes/IPs)
- **macOS aesthetic**: solid surfaces, subtle borders `#38383a`, compact density
- **Text**: primary `#e5e5e7`, secondary `#98989d`, muted `#636366`
