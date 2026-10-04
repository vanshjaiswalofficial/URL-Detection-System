# DESIGN — PhishGuard AI (UX, UI, content)

Status: Draft v0.1 · Applies to `dashboard/` and `extension/` · Read `RULES.md` §2, §8, §9 first.
Backend/ML design lives in `ARCHITECTURE.md`; this file is only about what people see and do.

---

## 1. Design intent

PhishGuard helps people decide, in seconds, whether a link is about to hurt them. The interface has one job: **make the reason for a warning obvious and believable.** A warning people don't understand gets clicked through.

**The one memorable idea — the URL anatomy strip.** Phishing works because people read the wrong part of a web address. We show every URL broken into labeled parts (scheme, subdomain, **registered domain**, suffix, path, query) and visually emphasize the registered domain — "where you actually are". Each reason in the explanation points at the part of the URL it is about. Everything else in the interface stays quiet so this device carries the personality.

### Principles

1. **Say what we know, and what we don't.** Never promise safety. "No threats found" is the best positive verdict we offer.
2. **Reasons before scores.** The number is secondary; the explanation is primary.
3. **Calm under danger.** Warnings are clear and firm, not panicky. No flashing, no skulls, no all-red walls.
4. **Safe default, honest escape hatch.** The safe action has focus; proceeding is possible but takes deliberate effort.
5. **Never color alone.** Every state has a distinct shape, label, and color.
6. **The link is untrusted text.** URLs are always rendered as inert text, defanged by default, with an explicit control to reveal.
7. **Fast and quiet when things are fine.** No interruption for `no_threat_found`.

## 2. Users and journeys

| Journey | Surface | Steps |
|---|---|---|
| **A. Clicked a bad link** | Extension | Navigate → check (≤ 500 ms typical) → warning page → "Go back to safety" or reveal details → optional "Report wrong warning" |
| **B. Not sure about a link** | Dashboard | Paste URL → Check → read anatomy + reasons → copy defanged URL / report |
| **C. Triage a list** | Dashboard (batch) | Paste up to 100 URLs → sortable table by risk → open a row for detail → export defanged CSV |
| **D. Check the current tab** | Extension popup | Click icon → status + reasons → "Check again" |
| **E. Fix a false alarm** | Extension / Dashboard | "Report wrong warning" → confirm → optionally "Always allow this site" |

## 3. Information architecture

**Dashboard**
- Check (home): input, result, recent checks
- Batch: multi-URL input and results table
- History: filterable list, feedback state
- Model: active version, thresholds summary, evaluation summary, limitations
- Settings: API key, privacy (store URLs on/off, retention), strictness, lists

**Extension**
- Toolbar badge, popup, warning page (`warning.html`), options page

## 4. Visual language

### 4.1 Design plan (and review against defaults)

- **Color:** cool "inspection-table" neutrals plus one action color and three verdict colors. *Reviewed:* rejected the cream-paper + terracotta look and the black + neon look as generic; security tools default to dark/neon, so we use a light, clinical, high-legibility base with dark mode as an equal.
- **Type:** one humanist sans for interface (Public Sans); one monospace used **only** for URLs and code-like strings, where fixed-width alignment is functional (character-by-character inspection), not decorative.
- **Layout:** a single reading column ("case file") on the dashboard, not a grid of identical cards. Result is a document: verdict line → anatomy strip → reasons → actions. *Reviewed:* removed eyebrow labels, middle-dot meta strings, arrow-suffixed links, and gradient washes.
- **Spend boldness in one place:** the anatomy strip (large, mono, annotated). Everything else is restrained.

### 4.2 Tokens

Define once as CSS variables (dashboard) and copy into the extension's CSS (no remote assets in the extension). Verify every text/background pair reaches **≥ 4.5:1** (3:1 for large text and UI components) with a tool before shipping; adjust hex values rather than exceptions.

```css
:root {
  /* Surfaces & text */
  --ink:        #16212E;   /* primary text */
  --ink-muted:  #4A5868;   /* secondary text */
  --paper:      #F4F6F8;   /* page background */
  --panel:      #FFFFFF;   /* raised surface */
  --rule:       #D3DAE2;   /* borders, dividers */

  /* Action */
  --cobalt:     #2457C5;   /* primary buttons, links, focus ring base */
  --cobalt-ink: #FFFFFF;

  /* Verdicts: text/icon color + tint fill */
  --ok:         #137A5E;   --ok-tint:   #E3F3EE;    /* No threats found */
  --warn:       #8A5A00;   --warn-tint: #FBF0D5;    /* Suspicious */
  --danger:     #B3263A;   --danger-tint:#FBE7EA;   /* Dangerous */
  --unknown:    #5B6676;   --unknown-tint:#ECEFF3;  /* Couldn't check */

  /* URL anatomy segments (also differentiated by underline style + label) */
  --seg-scheme: #5B6676;
  --seg-sub:    #8A5A00;
  --seg-domain: #16212E;   /* emphasized with --seg-domain-bg */
  --seg-domain-bg: #DCE6FA;
  --seg-suffix: #2457C5;
  --seg-path:   #4A5868;
  --seg-query:  #7A8696;

  /* Type */
  --font-ui:   "Public Sans", system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
  --font-url:  "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;

  /* Scale (rem) */
  --t-xs: 0.75rem; --t-sm: 0.875rem; --t-md: 1rem; --t-lg: 1.25rem; --t-xl: 1.75rem; --t-url: 1.125rem;
  --lh-ui: 1.5;  --measure: 68ch;

  /* Space & shape */
  --s-1: 4px; --s-2: 8px; --s-3: 12px; --s-4: 16px; --s-5: 24px; --s-6: 32px; --s-7: 48px;
  --r-sm: 4px; --r-md: 8px;           /* two radii only; buttons sm, containers md */
  --focus: 0 0 0 3px #FFFFFF, 0 0 0 5px var(--cobalt);
}

@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --ink: #E6EDF5; --ink-muted: #A9B6C6; --paper: #0E1620; --panel: #162231; --rule: #2A3A4D;
    --cobalt: #7CA2F2; --cobalt-ink: #0E1620;
    --ok: #55C9A3; --ok-tint: #11382E;
    --warn: #F2B33D; --warn-tint: #3A2C0C;
    --danger: #FF8A98; --danger-tint: #44181F;
    --unknown: #A9B6C6; --unknown-tint: #223142;
    --seg-domain: #E6EDF5; --seg-domain-bg: #1F3558; --seg-sub: #F2B33D; --seg-suffix: #7CA2F2;
    --focus: 0 0 0 3px #0E1620, 0 0 0 5px var(--cobalt);
  }
}
```

**Type usage:** UI text 14–16 px; verdict line 20–28 px, weight 600; URLs 16–18 px mono with generous letter-spacing; max line length 68ch for prose. Sentence case everywhere. No all-caps labels.

**Fonts:** dashboard may self-host or use a font service; **extension must bundle woff2 locally** (MV3 CSP). Always provide the fallback stacks above.

**Elevation & shape:** flat surfaces, 1 px `--rule` borders, minimal shadow. Two radii only (`--r-sm` for controls, `--r-md` for containers).

**Motion:** one moment — when a result arrives, anatomy segments settle in left to right (≈120 ms each). Hovering/focusing a reason highlights its URL segment. Everything respects `prefers-reduced-motion` (no animation, instant state).

### 4.3 Verdict system

| API verdict | UI name | Shape (icon) | Color tokens | Notes |
|---|---|---|---|---|
| `malicious` | **Dangerous site** | Octagon with bar | `--danger` / `--danger-tint` | Interstitial in extension |
| `suspicious` | **Suspicious site** | Triangle with mark | `--warn` / `--warn-tint` | Badge + popup; interstitial only in strict mode |
| `no_threat_found` | **No threats found** | Circle with dot (not a check mark) | `--ok` / `--ok-tint` | Always followed by "This isn't a guarantee." in details |
| `unknown` | **Couldn't check** | Dashed circle with question mark | `--unknown` / `--unknown-tint` | Never styled as safe |

Risk score (0–100) appears as a small secondary figure with a plain-language band; it never replaces the verdict.

## 5. Components

| Component | Purpose | Key behavior |
|---|---|---|
| **UrlAnatomy** | The signature element | Renders canonical URL as inert text split into scheme / subdomain / registered domain / suffix / path / query. Registered domain gets the highlight band. Labels sit beneath each segment (so color isn't the only cue). Long paths truncate in the middle with a "show full" control. Defanged by default; "Show real address" toggles. |
| **VerdictLine** | State summary | Icon + name + risk figure; `aria-live="polite"` on update. |
| **ReasonList** | Why | Each reason: severity icon, one plain sentence, optional "about this part" link that highlights the segment in UrlAnatomy. Max 5 shown; "See all signals" expands. |
| **Evidence drawer** | For analysts | Layers hit (feeds/ML/enrichment), model version, probability, thresholds, latency. |
| **FeedbackControl** | Learn from mistakes | "Report wrong result" → choose: "This site is safe" / "This site is dangerous" → confirm; shows what happens next ("A person reviews reports before they change anything"). |
| **BatchTable** | Triage | Sortable by risk, filter by verdict, keyboard navigable, export defanged CSV. |
| **Interstitial** | Extension warning | See §6.3. |
| **PopupStatus** | Extension popup | Current tab status, top 2 reasons, "Check again", settings link. |
| **Toast / inline status** | Confirmations | Action names are mirrored ("Report wrong result" → "Report sent"). |

## 6. Screens and wireframes

### 6.1 Dashboard — Check (home)

```
┌───────────────────────────────────────────────────────────────────┐
│ PhishGuard                                 Batch   History   Model│
├───────────────────────────────────────────────────────────────────┤
│  Check a link                                                     │
│  ┌───────────────────────────────────────────────┐ ┌───────────┐  │
│  │ Paste a web address                           │ │  Check    │  │
│  └───────────────────────────────────────────────┘ └───────────┘  │
│  We don't open the link. We read its text and compare it with     │
│  patterns seen in known scams.                                    │
│                                                                   │
│  ▲ Suspicious site                                  Risk 64 of 100│
│                                                                   │
│  https://secure-login.paypa1-support.example.com/verify           │
│  ‾‾‾‾‾‾‾  ~~~~~~~~~~~~ ═══════════════════════════ ‾‾‾ ········   │
│  scheme   subdomain    registered domain          suffix path     │
│                                                                   │
│  Why we flagged it                                                │
│  ▲ The name of a well-known brand appears in the address,         │
│    but the site isn't run by that brand.        [highlight part]  │
│  ▲ The domain looks like a misspelling of a popular site.         │
│  ● The address asks you to "verify" an account.                   │
│                                                                   │
│  [ Report wrong result ]   [ Copy safe-to-share address ]         │
│  Details: model 2026.10.0, checked in 38 ms                       │
└───────────────────────────────────────────────────────────────────┘
```

### 6.2 Extension popup (≈ 360 × 380 px)

```
┌────────────────────────────────────┐
│ ⬣ Dangerous site                   │
│ hxxps://paypa1-support[.]example…  │
│ ────────────────────────────────── │
│ Why                                │
│ ▲ Brand name used in the address   │
│ ▲ Looks like a misspelled domain   │
│                                    │
│ [ Go back ]  [ Report wrong result]│
│ Check again          Settings      │
└────────────────────────────────────┘
```

### 6.3 Extension interstitial (`warning.html`)

```
┌───────────────────────────────────────────────────────────────────┐
│ ▌ ⬣  This site may try to steal your information                  │
│ ▌                                                                 │
│ ▌   You were about to visit:                                      │
│ ▌   [ UrlAnatomy, defanged ]                                      │
│ ▌                                                                 │
│ ▌   Why we stopped you                                            │
│ ▌   ▲ …reasons…                                                   │
│ ▌                                                                 │
│ ▌   [  Go back to safety  ]   (focused by default)                │
│ ▌                                                                 │
│ ▌   ▸ I understand the risk                                       │
│ ▌       [ Open this site once ]   [ Always allow this site ]      │
│ ▌   Report wrong warning                                          │
└───────────────────────────────────────────────────────────────────┘
```
Left band uses `--danger`; body stays neutral `--panel`. The proceed controls live inside a disclosure so the safe action is the path of least effort.

### 6.4 Batch

Textarea (one URL per line, ≤ 100) → table: Risk (sortable), Verdict, Registered domain, Top reason, Action menu. Row opens the same result view in a side panel. Export is defanged by default.

## 7. States

| State | Dashboard | Extension |
|---|---|---|
| Loading | Skeleton of the result block; button shows "Checking"; input disabled | Badge spinner glyph after 300 ms; no interruption |
| Empty (history) | "No checks yet. Paste a link above to start." | — |
| Invalid input | Inline: "That doesn't look like a web address. Try something like example.com/page." | — |
| Offline / API down | Banner: "Can't reach the PhishGuard service. Checks use saved lists only." | Badge "?" + popup "Couldn't check this site. Be careful with links you didn't expect." |
| Rate limited | "Too many checks. Try again in 30 seconds." | Silent retry with backoff; badge "?" |
| Unknown (private host etc.) | "We can't check this kind of address (private network or unsupported type)." | Not scanned; no badge |
| Stale feed / model | Model page shows last feed sync time with warning if > 24 h | — |

## 8. Content guidelines

- Plain words, sentence case, active voice. Name things by what people understand: "web address", not "URI"; "wrong warning", not "false positive".
- Buttons say exactly what happens: **Check**, **Go back to safety**, **Open this site once**, **Report wrong result**. The same action keeps the same name across the flow (button "Report wrong result" → confirmation "Report sent").
- Errors explain what happened and what to do, in the interface's voice, without apology or jargon.
- No fear language ("hacked!", "virus!"). Describe the risk calmly: "This site may try to steal your information."
- Never say "safe" as a verdict. Use "No threats found" and, in details, "This check can't guarantee a site is safe."
- Reason sentences are ≤ 20 words and start with the observation, not the model internals.
- All strings come from the strings module (`R-CODE-11`); no concatenated sentences; allow ~40% text expansion; avoid idioms to ease translation (right-to-left layouts must not break).

**Reason copy examples (map from `core/reasons.yaml`)**

| Code | Text |
|---|---|
| `brand_in_subdomain_not_regdomain` | The name of a well-known brand appears in the address, but the site isn't run by that brand. |
| `typosquat_brand` | The domain looks like a misspelling of a popular site. |
| `ip_host` | The address uses numbers instead of a name, which real services rarely do. |
| `userinfo_trick` | Part of the address before an "@" is hiding the real destination. |
| `punycode_mixed_script` | The address mixes letters from different alphabets that look alike. |
| `long_random_subdomain` | The address has a long string of random-looking characters. |
| `feed_hit` | This address was reported as a scam by a threat-intelligence source. |
| `new_domain` | The domain was registered very recently. (enrichment) |

## 9. Accessibility (WCAG 2.2 AA target)

- Contrast ≥ 4.5:1 text, 3:1 for icons/controls/focus; verify in both themes.
- Full keyboard operation; logical focus order; visible focus ring (`--focus`); interstitial focuses "Go back to safety".
- Screen readers: verdict announced via `aria-live="polite"`; UrlAnatomy has a text alternative ("Scheme https. Subdomain secure-login. Registered domain paypa1-support dot example dot com. Path /verify."); icons have labels; reasons are a real list.
- Hit targets ≥ 24×24 CSS px (prefer 40 px for primary actions).
- No time limits on decisions; no autoplay; respects `prefers-reduced-motion` and `prefers-color-scheme`.
- Don't rely on hover for essential info (the segment highlight is also on focus/tap).
- Test with axe-core in CI plus a manual screen-reader pass per release.

## 10. Extension specifics

- **Badge:** Dangerous = red badge with "!"; Suspicious = amber with "!"; Couldn't check = gray "?"; No threats found = **no badge** (quiet). Badge text is supplemented by tooltip text.
- **Popup:** ≤ 380 px tall; shows status only for the active tab; no content scripts reading the page in v1.
- **Options:** privacy mode (local-only), strictness (warn on suspicious), API endpoint/key, manage allowed sites, delete my data.
- **Permissions copy:** a plain-language explanation page ("Why PhishGuard needs to see the addresses you visit and what it does with them"), linked from options and the store listing.

## 11. Responsive behavior (dashboard)

Single column at all widths; max content width ~ 880 px; the anatomy strip scrolls horizontally inside its own container on narrow screens (never makes the page scroll sideways); tables collapse to stacked rows under 640 px.

## 12. Handoff checklist

- [ ] Tokens implemented once; light and dark verified for contrast.
- [ ] UrlAnatomy has unit tests with tricky URLs (userinfo `@`, punycode, long paths, IP hosts).
- [ ] No `innerHTML` with URL-derived data; defanging default verified.
- [ ] All verdict states and error states have screenshots in the PR.
- [ ] Strings externalized; pseudo-localization pass done.
- [ ] axe-core clean; keyboard walkthrough recorded.
