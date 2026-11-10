import { createElement as h, useEffect, useRef, useState } from 'react'
import { PANES_AREA, PALETTE_AREA, ROUTES_AREA, SIDEBAR_NAV_AREA, host, relativeTime } from '@hermes/plugin-sdk'

const POLL_MS = 1000
const TICK_MS = 250
const FRESH_MS = 3200
const SIZE = 236
const MID = SIZE / 2
const TAU = Math.PI * 2

const EVENT_TONE = {
  presented: 'accent', vote: 'blue', decided: 'green', armed: 'green', tripwire: 'red', refused: 'red',
  command_refused: 'orange', tool_refused: 'orange', delivery_failed: 'yellow'
}
const OUTCOME_TONE = { once: 'green', deny: 'red' }
const TONE_VAR = {
  accent: 'var(--ui-accent)', green: 'var(--ui-green)', red: 'var(--ui-red)', yellow: 'var(--ui-yellow)',
  orange: 'var(--ui-orange)', blue: 'var(--ui-blue)', muted: 'var(--ui-text-quaternary)'
}
const WHY = { requester: 'asked for this command', 'not-eligible': 'not an approver' }

const STYLE = `
.sk{--sk-green:var(--ui-green);--sk-red:var(--ui-red);--sk-line:color-mix(in srgb,var(--ui-base) 14%,transparent);container-type:inline-size;height:100%;overflow:auto;color:var(--ui-text-primary);font-size:13px;line-height:1.4}
.sk *{box-sizing:border-box}
.sk-num{font-variant-numeric:tabular-nums}
.sk-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.sk-wrap{display:flex;flex-direction:column;gap:16px;padding:16px;min-height:100%}
.sk-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap}
.sk-brand{display:flex;align-items:center;gap:12px;min-width:0}
.sk-key{width:38px;height:38px;flex:none;color:var(--ui-accent)}
.sk-title{font-size:22px;font-weight:680;letter-spacing:-.015em;line-height:1.1}
.sk-tag{margin-top:4px;color:var(--ui-text-secondary);font-size:12.5px;max-width:64ch}
.sk-tag b{color:var(--ui-text-primary);font-weight:620}
.sk-pills{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.sk-pill{display:inline-flex;align-items:center;gap:7px;font-size:11px;font-weight:650;letter-spacing:.12em;text-transform:uppercase;padding:5px 11px;border-radius:999px;border:1px solid var(--ui-stroke-secondary);color:var(--ui-text-secondary);background:var(--ui-bg-secondary)}
.sk-pill i{width:7px;height:7px;border-radius:50%;background:var(--ui-text-quaternary)}
.sk-pill[data-tone="green"]{color:var(--ui-green);border-color:color-mix(in srgb,var(--ui-green) 45%,transparent);background:color-mix(in srgb,var(--ui-green) 10%,transparent)}
.sk-pill[data-tone="green"] i{background:var(--ui-green);animation:sk-live 2.2s infinite}
.sk-pill[data-tone="red"]{color:var(--ui-red);border-color:color-mix(in srgb,var(--ui-red) 55%,transparent);background:color-mix(in srgb,var(--ui-red) 12%,transparent);animation:sk-alarm 1.1s ease-in-out infinite}
.sk-pill[data-tone="red"] i{background:var(--ui-red)}
.sk-pill[data-tone="yellow"]{color:var(--ui-yellow);border-color:color-mix(in srgb,var(--ui-yellow) 45%,transparent)}
.sk-pill[data-tone="yellow"] i{background:var(--ui-yellow)}
.sk-pill .sk-fp{font-weight:500;letter-spacing:.04em;text-transform:none;color:var(--ui-text-tertiary)}
.sk-main{display:grid;gap:16px;grid-template-columns:minmax(0,1fr);align-items:start}
.sk-col{display:flex;flex-direction:column;gap:16px;min-width:0}
.sk-card{position:relative;border-radius:16px;background:var(--ui-bg-secondary);border:1px solid var(--ui-stroke-tertiary);min-width:0;overflow:hidden}
.sk-card[data-tier="critical"]{border-color:color-mix(in srgb,var(--ui-red) 42%,var(--ui-stroke-tertiary));box-shadow:0 0 0 1px color-mix(in srgb,var(--ui-red) 12%,transparent),0 18px 48px -28px var(--ui-red)}
.sk-card[data-tier="critical"]::before{content:"";position:absolute;inset:0 0 auto 0;height:3px;background:linear-gradient(90deg,var(--ui-red),color-mix(in srgb,var(--ui-red) 0%,transparent))}
.sk-card-h{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:12px 16px 4px;font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ui-text-tertiary);font-weight:650}
.sk-ballot{display:grid;grid-template-columns:minmax(0,1fr);gap:18px;padding:12px 18px 18px;align-items:center}
.sk-ringbox{position:relative;width:min(100%,${SIZE}px);aspect-ratio:1;margin:0 auto}
.sk-ring{display:block;width:100%;height:100%;overflow:visible}
.sk-ring-c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;text-align:center}
.sk-time{font-size:42px;font-weight:680;letter-spacing:-.03em;line-height:1}
.sk-time-l{font-size:10px;letter-spacing:.2em;text-transform:uppercase;color:var(--ui-text-tertiary)}
.sk-tally{margin-top:8px;font-size:15px;font-weight:620}
.sk-tally b{font-size:22px}
.sk-body{display:flex;flex-direction:column;gap:14px;min-width:0}
.sk-badges{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.sk-badge{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;padding:4px 10px;border-radius:7px;color:var(--ui-text-secondary);background:var(--ui-bg-tertiary)}
.sk-badge[data-tone="red"]{color:var(--ui-red);background:color-mix(in srgb,var(--ui-red) 14%,transparent)}
.sk-badge[data-tone="yellow"]{color:var(--ui-yellow);background:color-mix(in srgb,var(--ui-yellow) 14%,transparent)}
.sk-badge[data-tone="green"]{color:var(--ui-green);background:color-mix(in srgb,var(--ui-green) 14%,transparent)}
.sk-badge[data-tone="accent"]{color:var(--ui-accent);background:color-mix(in srgb,var(--ui-accent) 14%,transparent)}
.sk-who{color:var(--ui-text-secondary);font-size:13px}
.sk-who b{color:var(--ui-text-primary);font-weight:620}
.sk-cmd{margin:0;padding:14px 16px;border-radius:11px;background:var(--ui-bg-editor);border:1px solid var(--ui-stroke-secondary);font-size:15px;line-height:1.5;white-space:pre-wrap;word-break:break-all;color:var(--ui-text-primary);max-height:140px;overflow:auto}
.sk-prompt{color:var(--ui-accent);margin-right:9px;user-select:none}
.sk-rule{color:var(--ui-text-secondary);font-size:13px}
.sk-rule b{color:var(--ui-text-primary)}
.sk-people{display:flex;gap:18px;flex-wrap:wrap}
.sk-person{display:flex;flex-direction:column;align-items:center;gap:7px;width:104px;text-align:center}
.sk-av{position:relative;width:68px;height:68px;border-radius:50%;display:grid;place-items:center;font-size:23px;font-weight:660;letter-spacing:.02em;color:var(--ui-text-secondary);background:var(--ui-bg-tertiary);transition:background .35s,color .35s,box-shadow .35s}
.sk-av::before{content:"";position:absolute;inset:-6px;border-radius:50%;border:2px dashed var(--ui-stroke-primary);animation:sk-spin 14s linear infinite}
.sk-av-mark{position:absolute;right:-4px;bottom:-4px;width:24px;height:24px;border-radius:50%;display:grid;place-items:center;background:var(--ui-bg-secondary);border:2px solid var(--ui-bg-secondary)}
.sk-av-mark svg{width:15px;height:15px}
.sk-person[data-state="yes"] .sk-av{color:var(--ui-green);background:color-mix(in srgb,var(--ui-green) 20%,var(--ui-bg-tertiary));box-shadow:0 0 0 2px var(--ui-green),0 0 34px -4px var(--ui-green);animation:sk-pop .6s cubic-bezier(.2,1.6,.4,1)}
.sk-person[data-state="yes"] .sk-av::before{border-style:solid;border-color:color-mix(in srgb,var(--ui-green) 45%,transparent);animation:none}
.sk-person[data-state="yes"] .sk-av-mark{background:var(--ui-green);border-color:var(--ui-bg-secondary);color:var(--ui-bg-secondary)}
.sk-person[data-state="no"] .sk-av{color:var(--ui-red);background:color-mix(in srgb,var(--ui-red) 20%,var(--ui-bg-tertiary));box-shadow:0 0 0 2px var(--ui-red),0 0 34px -4px var(--ui-red);animation:sk-pop .6s cubic-bezier(.2,1.6,.4,1)}
.sk-person[data-state="no"] .sk-av::before{animation:none;border-style:solid;border-color:color-mix(in srgb,var(--ui-red) 45%,transparent)}
.sk-person[data-state="no"] .sk-av-mark{background:var(--ui-red);color:var(--ui-bg-secondary)}
.sk-person[data-state="requester"] .sk-av{opacity:.5;filter:saturate(.3)}
.sk-person[data-state="requester"] .sk-av::before{animation:none;border-color:var(--ui-stroke-secondary)}
.sk-person[data-state="requester"] .sk-av::after{content:"";position:absolute;left:8px;right:8px;top:50%;height:3px;border-radius:2px;background:var(--ui-red);transform:rotate(-38deg)}
.sk-person[data-state="waiting"] .sk-av{box-shadow:0 0 0 1px var(--ui-stroke-secondary)}
.sk-pname{font-weight:620;font-size:13.5px;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-pstate{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;color:var(--ui-text-tertiary)}
.sk-person[data-state="yes"] .sk-pstate{color:var(--ui-green)}
.sk-person[data-state="no"] .sk-pstate,.sk-person[data-state="requester"] .sk-pstate{color:var(--ui-red)}
.sk-nc{display:flex;flex-direction:column;gap:6px}
.sk-nc-i{display:flex;align-items:center;gap:10px;padding:8px 12px;border-radius:10px;font-size:13px;color:var(--ui-text-primary);background:color-mix(in srgb,var(--ui-red) 11%,transparent);border:1px solid color-mix(in srgb,var(--ui-red) 38%,transparent);animation:sk-shake .5s ease-out}
.sk-nc-i svg{width:16px;height:16px;flex:none;color:var(--ui-red)}
.sk-nc-i b{font-weight:680}
.sk-nc-i em{font-style:normal;margin-left:auto;font-size:10.5px;letter-spacing:.14em;text-transform:uppercase;color:var(--ui-red);font-weight:700;white-space:nowrap}
.sk-tiers{list-style:none;margin:0;padding:2px 16px 14px;display:flex;flex-direction:column;gap:11px}
.sk-tier{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:4px 12px;align-items:center}
.sk-tier-n{font-size:12.5px;color:var(--ui-text-secondary)}
.sk-tier-n b{color:var(--ui-text-primary);font-weight:620}
.sk-tier[data-tier="critical"] .sk-tier-n b{color:var(--ui-red)}
.sk-pips{display:flex;gap:4px;justify-content:flex-end}
.sk-pip{width:20px;height:8px;border-radius:3px;background:var(--ui-stroke-secondary)}
.sk-pip[data-on="true"]{background:var(--ui-accent)}
.sk-tier[data-tier="critical"] .sk-pip[data-on="true"]{background:var(--ui-red);box-shadow:0 0 8px -1px var(--ui-red)}
.sk-idle{display:grid;grid-template-columns:minmax(0,1fr);gap:18px;padding:12px 18px 18px;align-items:center}
.sk-idle h3{margin:0 0 6px;font-size:20px;font-weight:660;letter-spacing:-.01em}
.sk-idle p{margin:0;color:var(--ui-text-secondary);max-width:58ch}
.sk-gate-s{display:flex;align-items:center;gap:12px;padding:6px 16px 10px}
.sk-shield{width:34px;height:34px;flex:none}
.sk-gate-t{font-size:17px;font-weight:680;letter-spacing:-.01em}
.sk-gate-d{font-size:12px;color:var(--ui-text-secondary)}
.sk-reasons{margin:0 16px 8px;padding:9px 12px;border-radius:9px;background:color-mix(in srgb,var(--ui-red) 12%,transparent);border:1px solid color-mix(in srgb,var(--ui-red) 40%,transparent);color:var(--ui-text-primary);font-size:12px}
.sk-set{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;margin:0 10px 12px;padding:0;list-style:none}
.sk-set li{display:flex;justify-content:space-between;gap:8px;align-items:baseline;padding:3px 8px;border-radius:7px;font-size:11.5px;min-width:0}
.sk-set li[data-changed="true"]{grid-column:1/-1;background:color-mix(in srgb,var(--ui-red) 16%,transparent);color:var(--ui-red)}
.sk-set span{color:var(--ui-text-tertiary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-set b{font-weight:560;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:52%}
.sk-set li[data-changed="true"] span{color:inherit}
.sk-set li[data-changed="true"] b{max-width:none}
.sk-list{list-style:none;margin:0;padding:0 8px 10px;display:flex;flex-direction:column;gap:2px}
.sk-dec{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:10px;align-items:center;padding:8px;border-radius:10px;font-size:12.5px}
.sk-dec:hover{background:var(--ui-row-hover-background)}
.sk-dec code{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12.5px}
.sk-dec small{display:block;color:var(--ui-text-tertiary);font-size:11px;margin-top:1px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-empty{padding:6px 16px 16px;color:var(--ui-text-tertiary)}
.sk-chain{padding:0 0 14px}
.sk-chain-h{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:12px 16px 8px;flex-wrap:wrap}
.sk-chain-t{display:flex;align-items:center;gap:10px;font-size:10.5px;letter-spacing:.16em;text-transform:uppercase;color:var(--ui-text-tertiary);font-weight:650}
.sk-verdict{font-size:12px;font-weight:650;letter-spacing:.04em;padding:4px 11px;border-radius:999px}
.sk-verdict[data-ok="true"]{color:var(--ui-green);background:color-mix(in srgb,var(--ui-green) 13%,transparent)}
.sk-verdict[data-ok="false"]{color:var(--ui-red);background:color-mix(in srgb,var(--ui-red) 16%,transparent);animation:sk-alarm 1.1s ease-in-out infinite}
.sk-strip{display:flex;align-items:stretch;overflow-x:auto;padding:6px 16px 10px;scrollbar-width:thin;list-style:none;margin:0}
.sk-link{display:flex;align-items:center;flex:none;width:44px;position:relative}
.sk-link::before{content:"";flex:1;height:2px;background:linear-gradient(90deg,var(--ui-stroke-primary),var(--ui-accent));border-radius:1px}
.sk-link::after{content:"";width:7px;height:7px;border-top:2px solid var(--ui-accent);border-right:2px solid var(--ui-accent);transform:rotate(45deg);margin-left:-8px}
.sk-link[data-ok="false"]::before{background:repeating-linear-gradient(90deg,var(--ui-red) 0 5px,transparent 5px 9px)}
.sk-link[data-ok="false"]::after{border-color:var(--ui-red)}
.sk-link[data-ok="false"] .sk-cut{display:grid}
.sk-cut{display:none;position:absolute;left:50%;top:50%;width:22px;height:22px;margin:-11px 0 0 -11px;border-radius:50%;place-items:center;background:var(--ui-red);color:var(--ui-bg-secondary);font-size:13px;font-weight:800;z-index:1}
.sk-block{flex:none;width:176px;display:flex;flex-direction:column;gap:7px;padding:11px 12px 12px;border-radius:12px;background:var(--ui-bg-editor);border:1px solid var(--ui-stroke-secondary);border-top:3px solid var(--sk-tone,var(--ui-accent));animation:sk-in .55s cubic-bezier(.2,.9,.3,1) both;animation-delay:calc(var(--i,0) * 45ms)}
.sk-block[data-new="true"]{animation:sk-slide .8s cubic-bezier(.2,.9,.3,1) both;box-shadow:0 0 0 1px var(--sk-tone),0 0 28px -6px var(--sk-tone)}
.sk-block[data-ok="false"]{border-color:var(--ui-red);background:color-mix(in srgb,var(--ui-red) 9%,var(--ui-bg-editor));border-top-color:var(--ui-red)}
.sk-bh{display:flex;justify-content:space-between;align-items:baseline;gap:6px}
.sk-ev{font-size:11.5px;font-weight:720;letter-spacing:.08em;text-transform:uppercase;color:var(--sk-tone,var(--ui-accent));overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sk-n{font-size:11px;color:var(--ui-text-quaternary)}
.sk-det{font-size:12px;color:var(--ui-text-primary);min-height:2.8em;overflow:hidden;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical}
.sk-ts{font-size:10.5px;color:var(--ui-text-tertiary)}
.sk-fp8{display:flex;gap:2px}
.sk-fp8 i{flex:1;height:5px;border-radius:2px;background:var(--sk-tone,var(--ui-accent))}
.sk-hash{font-size:10.5px;color:var(--ui-text-secondary);display:flex;justify-content:space-between;gap:6px}
.sk-hash span:first-child{color:var(--ui-text-quaternary)}
.sk-err{margin:0;padding:10px 16px;color:var(--ui-red)}
.sk-loading{display:grid;place-items:center;height:100%;color:var(--ui-text-tertiary)}
@container (min-width: 700px){
  .sk-ballot,.sk-idle{grid-template-columns:${SIZE}px minmax(0,1fr);gap:28px}
}
@container (min-width: 1000px){
  .sk-main{grid-template-columns:minmax(0,1fr) 440px}
  .sk-wrap{padding:20px 24px;gap:18px}
}
@keyframes sk-live{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--ui-green) 55%,transparent)}70%,100%{box-shadow:0 0 0 7px transparent}}
@keyframes sk-alarm{0%,100%{opacity:1}50%{opacity:.55}}
@keyframes sk-spin{to{transform:rotate(360deg)}}
@keyframes sk-pop{0%{transform:scale(.7)}100%{transform:scale(1)}}
@keyframes sk-shake{0%{transform:translateX(0);opacity:0}15%{transform:translateX(-7px);opacity:1}35%{transform:translateX(6px)}55%{transform:translateX(-4px)}75%{transform:translateX(2px)}100%{transform:translateX(0)}}
@keyframes sk-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes sk-slide{from{opacity:0;transform:translateX(70px) scale(.94)}to{opacity:1;transform:none}}
@media (prefers-reduced-motion: reduce){.sk *,.sk *::before,.sk *::after{animation:none!important;transition:none!important}}
`

// Untrusted text (commands, names, ledger fields) is only ever rendered as React text nodes. This also
// drops control and bidi-override characters so a crafted string cannot reorder or hide what an approver reads.
const plain = v => Array.from(String(v ?? '')).filter(ch => { const c = ch.codePointAt(0); return !(c === 127 || (c < 32 && c !== 9 && c !== 10) || c === 0x200e || c === 0x200f || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069)) }).join('')
const clip = (v, n) => { const s = plain(v); return s.length > n ? s.slice(0, n - 1) + '…' : s }
const num = (v, d = 0) => (Number.isFinite(Number(v)) ? Number(v) : d)
const list = v => (Array.isArray(v) ? v : [])
const initials = name => plain(name).trim().split(/\s+/).slice(0, 2).map(w => w.charAt(0)).join('').toUpperCase() || '?'
const clock = ms => { const s = Math.max(0, Math.ceil(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}` }
const tone = name => TONE_VAR[name] || TONE_VAR.accent

function pathArc(r, a0, a1) {
  const at = a => [MID + r * Math.cos(a), MID + r * Math.sin(a)]
  const [x0, y0] = at(a0)
  const [x1, y1] = at(a1)
  return `M${x0.toFixed(2)} ${y0.toFixed(2)}A${r} ${r} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`
}

const svg = (props, ...kids) => h('svg', { viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', strokeWidth: 2.4, strokeLinecap: 'round', strokeLinejoin: 'round', 'aria-hidden': true, ...props }, ...kids)
const ICON = {
  check: () => svg(null, h('path', { d: 'M5 12.5l4.5 4.5L19 7.5' })),
  cross: () => svg(null, h('path', { d: 'M6 6l12 12M18 6L6 18' })),
  ban: () => svg(null, h('circle', { cx: 12, cy: 12, r: 9 }), h('path', { d: 'M5.6 5.6l12.8 12.8' })),
  key: () => svg({ strokeWidth: 1.7 }, h('circle', { cx: 8, cy: 15, r: 4.5 }), h('path', { d: 'M11.3 11.7L20 3M16 7l3 3M13.5 9.5l2 2' })),
  shield: () => svg({ strokeWidth: 1.8 }, h('path', { d: 'M12 3l7.5 3v5.5c0 4.6-3.1 8.2-7.5 9.5-4.4-1.3-7.5-4.9-7.5-9.5V6L12 3z' }))
}

function useApprovals(ctx) {
  const [snap, setSnap] = useState(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let alive = true
    let busy = false
    const load = async () => {
      if (busy) return
      busy = true
      try {
        const data = await ctx.rest('/state')
        if (alive) { setSnap({ data, at: Date.now() }); setError('') }
      } catch (e) {
        if (alive) setError(clip(e && e.message ? e.message : 'unreachable', 160))
      } finally { busy = false }
    }
    load()
    const stop = ctx.setInterval(load, POLL_MS)
    return () => { alive = false; stop() }
  }, [ctx])
  return { snap, error }
}

function useClock(ctx) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => ctx.setInterval(() => setNow(Date.now()), TICK_MS), [ctx])
  return now
}

function Ring({ frac, label, required, yes, danger }) {
  const radius = 98
  const circ = TAU * radius
  const color = danger ? 'var(--ui-red)' : frac > 0.5 ? 'var(--ui-accent)' : frac > 0.2 ? 'var(--ui-yellow)' : 'var(--ui-red)'
  const ticks = []
  for (let i = 0; i < 60; i++) {
    const a = (i / 60) * TAU - Math.PI / 2
    const long = i % 5 === 0
    const r0 = long ? 108 : 111
    const lit = i / 60 < frac
    ticks.push(h('line', {
      key: i, x1: MID + r0 * Math.cos(a), y1: MID + r0 * Math.sin(a), x2: MID + 116 * Math.cos(a), y2: MID + 116 * Math.sin(a),
      stroke: lit ? color : 'var(--ui-stroke-secondary)', strokeWidth: long ? 2.2 : 1.2, strokeLinecap: 'round'
    }))
  }
  const segs = []
  const gap = required > 1 ? 0.16 : 0.05
  for (let i = 0; i < required; i++) {
    const a0 = -Math.PI / 2 + (i / required) * TAU + gap / 2
    const a1 = -Math.PI / 2 + ((i + 1) / required) * TAU - gap / 2
    const got = i < yes
    segs.push(h('path', {
      key: i, d: pathArc(77, a0, a1), fill: 'none', strokeWidth: 9, strokeLinecap: 'round',
      stroke: got ? 'var(--ui-green)' : 'var(--ui-stroke-secondary)',
      style: got ? { filter: 'drop-shadow(0 0 7px var(--ui-green))', transition: 'stroke .4s' } : { transition: 'stroke .4s' }
    }))
  }
  return h('div', { className: 'sk-ringbox' },
    h('svg', { className: 'sk-ring', viewBox: `0 0 ${SIZE} ${SIZE}`, role: 'img', 'aria-label': `${label} left, ${yes} of ${required} approvals` },
      ticks,
      h('circle', { cx: MID, cy: MID, r: radius, fill: 'none', stroke: 'var(--ui-stroke-tertiary)', strokeWidth: 9 }),
      h('circle', {
        cx: MID, cy: MID, r: radius, fill: 'none', stroke: color, strokeWidth: 9, strokeLinecap: 'round',
        strokeDasharray: circ, strokeDashoffset: circ * (1 - Math.max(0, Math.min(1, frac))), transform: `rotate(-90 ${MID} ${MID})`,
        style: { filter: `drop-shadow(0 0 8px ${color})`, transition: 'stroke .5s' }
      }),
      segs),
    h('div', { className: 'sk-ring-c' },
      h('div', { className: 'sk-time sk-num', style: { color } }, label),
      h('div', { className: 'sk-time-l' }, 'until deny'),
      h('div', { className: 'sk-tally sk-num' }, h('b', null, yes), ` of ${required} approved`)))
}

function Person({ person }) {
  const state = person.state
  const mark = state === 'yes' ? ICON.check() : state === 'no' ? ICON.cross() : null
  const caption = { yes: 'approved', no: 'denied', requester: 'asked for it', waiting: 'waiting' }[state] || state
  return h('div', { className: 'sk-person', 'data-state': state, title: state === 'requester' ? 'The requester can never approve their own request' : undefined },
    h('div', { className: 'sk-av' }, initials(person.name), mark && h('span', { className: 'sk-av-mark' }, mark)),
    h('div', { className: 'sk-pname' }, clip(person.name, 18)),
    h('div', { className: 'sk-pstate' }, caption))
}

function Ballot({ ballot, now, fetchedAt, serverNow }) {
  const deadline = (num(ballot.opened_at) + num(ballot.timeout)) * 1000
  const remaining = deadline - (serverNow + (now - fetchedAt))
  const total = Math.max(1, num(ballot.timeout) * 1000)
  const yes = list(ballot.approvers).filter(p => p.state === 'yes').length
  const required = Math.max(1, num(ballot.required, 1))
  const critical = ballot.tier === 'critical'
  const people = list(ballot.approvers)
  const requester = ballot.requester || {}
  const eligible = people.filter(p => p.state !== 'requester').map(p => p.name)
  return h('section', { className: 'sk-card', 'data-tier': ballot.tier, 'aria-label': 'Open ballot' },
    h('div', { className: 'sk-card-h' }, h('span', null, 'Open ballot'), h('span', { className: 'sk-mono' }, clip(ballot.request_id, 8))),
    h('div', { className: 'sk-ballot' },
      h(Ring, { frac: remaining / total, label: clock(remaining), required, yes, danger: remaining <= 0 }),
      h('div', { className: 'sk-body' },
        h('div', { className: 'sk-badges' },
          h('span', { className: 'sk-badge', 'data-tone': critical ? 'red' : ballot.tier === 'standard' ? 'accent' : 'yellow' },
            critical ? `Critical: ${clip(ballot.pattern_key || 'critical pattern', 40)}` : ballot.tier === 'standard' ? 'Standard risk' : 'Requester unknown'),
          h('span', { className: 'sk-who' }, 'asked by ', h('b', null, clip(requester.name || 'unknown', 32)), requester.platform ? ` on ${clip(requester.platform, 16)}` : '')),
        h('pre', { className: 'sk-cmd sk-mono' }, h('span', { className: 'sk-prompt' }, '$'), clip(ballot.command, 600)),
        h('div', { className: 'sk-rule' }, h('b', { className: 'sk-num' }, required), ` approval${required === 1 ? '' : 's'} needed from people other than the requester`,
          eligible.length ? ` (${clip(eligible.join(', '), 80)})` : ''),
        h('div', { className: 'sk-people' }, people.map(p => h(Person, { key: `${p.name}:${p.state}`, person: p }))),
        list(ballot.not_counted).length > 0 && h('div', { className: 'sk-nc', role: 'status' },
          list(ballot.not_counted).map((n, i) => h('div', { key: `${n.name}:${n.at}:${i}`, className: 'sk-nc-i' },
            ICON.ban(), h('span', null, h('b', null, clip(n.name, 24)), ' tapped a button'), h('em', null, `Not counted · ${WHY[n.why] || 'not allowed'}`)))))))
}

function Idle({ roster, last }) {
  const people = list(roster).map(p => ({ name: p.name, state: 'waiting' }))
  return h('section', { className: 'sk-card', 'aria-label': 'No open ballot' },
    h('div', { className: 'sk-card-h' }, h('span', null, 'Quorum desk'), h('span', null, 'standing by')),
    h('div', { className: 'sk-idle' },
      h(Ring, { frac: 1, label: '0:00', required: 2, yes: 0, danger: false }),
      h('div', null,
        h('h3', null, 'No ballot is open'),
        h('p', null, 'A dangerous command waits here for approvers who are not the person who asked. The countdown starts when it arrives.'),
        h('div', { className: 'sk-people', style: { marginTop: 16 } }, people.map(p => h(Person, { key: p.name, person: p }))),
        last && h('p', { style: { marginTop: 14 } }, 'Last decision: ', h('b', { style: { color: tone(OUTCOME_TONE[last.outcome]) } }, last.outcome === 'once' ? 'approved once' : 'denied'),
          ` for ${clip(last.requester && last.requester.name, 24)}`))))
}

function Gate({ armed }) {
  const state = armed.state
  const t = state === 'armed' ? 'green' : state === 'tripped' ? 'red' : 'yellow'
  const headline = state === 'armed' ? 'Armed' : state === 'tripped' ? 'Tripped: agent tools stopped' : 'Not armed'
  const detail = state === 'armed' ? 'Approval settings match what was armed.' : state === 'tripped' ? 'Settings changed after arming. Run /secondkey arm locally.' : 'Run /secondkey arm from a local session.'
  const reasons = list(armed.reasons)
  return h('section', { className: 'sk-card', 'aria-label': 'Gate status' },
    h('div', { className: 'sk-card-h' }, h('span', null, 'Settings watched'), h('span', { className: 'sk-mono' }, clip(armed.fingerprint, 8))),
    h('div', { className: 'sk-gate-s' },
      h('div', { className: 'sk-shield', style: { color: tone(t) } }, ICON.shield()),
      h('div', null, h('div', { className: 'sk-gate-t', style: { color: tone(t) } }, headline), h('div', { className: 'sk-gate-d' }, detail))),
    reasons.length > 0 && h('div', { className: 'sk-reasons', role: 'alert' }, reasons.map((r, i) => h('div', { key: i }, clip(r, 120)))),
    h('ul', { className: 'sk-set sk-mono' }, list(armed.watched).map(w => h('li', { key: w.key, 'data-changed': !!w.changed },
      h('span', null, clip(w.key, 26)), h('b', null, w.changed && w.now ? `${clip(w.value, 16)} \u2192 ${clip(w.now, 44)}` : clip(w.value, 22))))))
}

const TIER_NAME = { standard: 'Ordinary command', critical: 'Critical command', unknown: 'Requester unknown' }
const TIER_NOTE = { standard: 'Flagged by Hermes', critical: 'rm -rf, drop table, destroy, force push', unknown: 'Local session no approver claims' }

function Tiers({ tiers, roster }) {
  const n = Math.max(list(roster).length, 1)
  const rows = list(tiers)
  if (!rows.length) return null
  return h('section', { className: 'sk-card', 'aria-label': 'Votes needed by risk' },
    h('div', { className: 'sk-card-h' }, h('span', null, 'Sized to the risk'), h('span', { className: 'sk-num' }, `${n} on the roster`)),
    h('ul', { className: 'sk-tiers' }, rows.map(t => {
      const need = Math.min(Math.max(num(t.required, 1), 1), n)
      return h('li', { key: t.tier, className: 'sk-tier', 'data-tier': t.tier, title: TIER_NOTE[t.tier] || undefined },
        h('span', { className: 'sk-tier-n' }, h('b', null, TIER_NAME[t.tier] || clip(t.tier, 20)), ` needs ${num(t.required, 1)} of ${n}`),
        h('span', { className: 'sk-pips', role: 'img', 'aria-label': `${num(t.required, 1)} of ${n} approvals` },
          Array.from({ length: Math.min(n, 12) }, (_, i) => h('i', { key: i, className: 'sk-pip', 'data-on': i < need }))),
        )
    })))
}

function Decisions({ recent, last }) {
  const rows = list(recent).slice(0, 4)
  return h('section', { className: 'sk-card', 'aria-label': 'Recent decisions' },
    h('div', { className: 'sk-card-h' }, h('span', null, 'Recent decisions'), h('span', { className: 'sk-num' }, rows.length)),
    rows.length ? h('ul', { className: 'sk-list' }, rows.map(r => h('li', { key: `${r.request_id}:${r.closed_at}`, className: 'sk-dec' },
      h('span', { className: 'sk-badge', 'data-tone': OUTCOME_TONE[r.outcome] || 'yellow' }, r.outcome === 'once' ? 'Approved' : 'Denied'),
      h('div', { style: { minWidth: 0 } }, h('code', { className: 'sk-mono' }, clip(r.command, 60)),
        h('small', null, `${clip(r.requester && r.requester.name, 20)} asked · ${r.yes && r.yes.length ? 'yes: ' + clip(r.yes.join(', '), 40) : r.no ? 'denied by ' + clip(r.no, 24) : 'no approvals'}`)),
      h('small', { className: 'sk-num' }, r.closed_at ? relativeTime(num(r.closed_at) * 1000) : ''))))
      : h('div', { className: 'sk-empty' }, 'Decisions appear here the moment a ballot closes.'))
}

function Chain({ ledger, fresh }) {
  const entries = list(ledger.entries)
  const stripRef = useRef(null)
  const lastN = entries.length ? entries[entries.length - 1].n : 0
  useEffect(() => {
    const el = stripRef.current
    if (el) el.scrollLeft = el.scrollWidth
  }, [lastN])
  const ok = ledger.ok !== false
  return h('section', { className: 'sk-card sk-chain', 'aria-label': 'Decision ledger' },
    h('div', { className: 'sk-chain-h' },
      h('div', { className: 'sk-chain-t' }, h('span', null, 'Ledger'), h('span', { className: 'sk-num' }, `${num(ledger.total)} entries, each sealed with the hash of the one before`)),
      h('span', { className: 'sk-verdict sk-num', 'data-ok': ok }, ok ? `Chain intact · ${num(ledger.total)} links verified` : `Chain broken at entry ${num(ledger.broken_at)}`)),
    entries.length ? h('ol', { className: 'sk-strip', ref: stripRef }, entries.flatMap((e, i) => {
      const before = entries[i - 1]
      const linked = e.ok !== false && (!before || before.hash === e.prev)
      const t = e.event === 'decided' ? OUTCOME_TONE[String(e.detail).split(':')[0]] || 'accent' : EVENT_TONE[e.event] || 'accent'
      const hash = plain(e.hash)
      const cells = hash.slice(0, 8).split('').map((c, k) => h('i', { key: k, style: { opacity: (parseInt(c, 16) + 3) / 18 } }))
      const block = h('li', { key: `b${e.n}`, className: 'sk-block', 'data-ok': linked, 'data-new': fresh.has(e.n), style: { '--sk-tone': tone(t), '--i': Math.min(i, 14) } },
        h('div', { className: 'sk-bh' }, h('span', { className: 'sk-ev' }, clip(e.event, 16)), h('span', { className: 'sk-n sk-num' }, `#${num(e.n)}`)),
        h('div', { className: 'sk-det' }, clip(e.detail, 70)),
        h('div', { className: 'sk-ts sk-num' }, clip(String(e.ts).replace('T', ' ').replace('Z', ''), 19)),
        h('div', { className: 'sk-fp8', 'aria-hidden': true }, cells),
        h('div', { className: 'sk-hash sk-mono' }, h('span', null, 'hash'), h('span', null, hash.slice(0, 10))))
      return before ? [h('li', { key: `l${e.n}`, className: 'sk-link', 'data-ok': before.hash === e.prev && e.ok !== false, 'aria-hidden': true }, h('span', { className: 'sk-cut' }, '×')), block] : [block]
    })) : h('div', { className: 'sk-empty' }, 'The ledger starts with the first decision.'))
}

function Approvals({ ctx }) {
  const { snap, error } = useApprovals(ctx)
  const now = useClock(ctx)
  const [fresh, setFresh] = useState(() => new Set())
  const seen = useRef(null)
  const data = snap && snap.data
  const entries = data ? list(data.ledger && data.ledger.entries) : []
  useEffect(() => {
    if (!data) return
    const top = new Set(entries.map(e => e.n))
    if (seen.current === null) { seen.current = top; return }
    const added = [...top].filter(n => !seen.current.has(n))
    seen.current = top
    if (!added.length) return
    setFresh(f => new Set([...f, ...added]))
    ctx.setTimeout(() => setFresh(f => new Set([...f].filter(n => !added.includes(n)))), FRESH_MS)
  }, [data && data.ledger && data.ledger.total])

  if (!data) {
    return h('div', { className: 'sk' }, h('style', null, STYLE),
      error ? h('p', { className: 'sk-err', role: 'alert' }, `Approvals are unavailable: ${error}`) : h('div', { className: 'sk-loading', role: 'status' }, 'Reading the ledger…'))
  }
  const armed = data.armed || { state: 'not armed', watched: [], reasons: [] }
  const ballots = list(data.ballots)
  const pillTone = armed.state === 'armed' ? 'green' : armed.state === 'tripped' ? 'red' : 'yellow'
  return h('div', { className: 'sk' }, h('style', null, STYLE),
    h('div', { className: 'sk-wrap' },
      h('header', { className: 'sk-head' },
        h('div', { className: 'sk-brand' }, h('div', { className: 'sk-key' }, ICON.key()),
          h('div', null, h('div', { className: 'sk-title' }, 'Second key'), h('div', { className: 'sk-tag' }, h('b', null, 'A multisig for your AI agent.'), ' M of N teammates sized to the risk. The requester can\u2019t sign. The agent can\u2019t change the signers.'))),
        h('div', { className: 'sk-pills' },
          h('span', { className: 'sk-pill', 'data-tone': pillTone }, h('i'), armed.state, armed.fingerprint && h('span', { className: 'sk-fp sk-mono' }, clip(armed.fingerprint, 8))),
          h('span', { className: 'sk-pill', 'data-tone': error ? 'yellow' : 'green', title: error || 'Updating every second' }, h('i'), error ? 'Reconnecting' : 'Live'))),
      h('div', { className: 'sk-main' },
        h('div', { className: 'sk-col' },
          ballots.length
            ? ballots.map(b => h(Ballot, { key: b.request_id, ballot: b, now, fetchedAt: snap.at, serverNow: num(data.now) * 1000 }))
            : h(Idle, { roster: data.roster, last: list(data.recent)[0] }),
          h(Decisions, { recent: data.recent })),
        h('div', { className: 'sk-col' }, h(Gate, { armed }), h(Tiers, { tiers: data.tiers, roster: data.roster }))),
      h(Chain, { ledger: data.ledger || {}, fresh })))
}

export default {
  id: 'second-key',
  name: 'Second key',
  register(ctx) {
    ctx.registerMany([
      { id: 'pane', area: PANES_AREA, title: 'Approvals', data: { placement: 'right', width: '460px' }, render: () => h(Approvals, { ctx }) },
      { id: 'page', area: ROUTES_AREA, data: { path: '/second-key' }, render: () => h(Approvals, { ctx }) },
      { id: 'nav', area: SIDEBAR_NAV_AREA, data: { path: '/second-key', label: 'Approvals', codicon: 'key' } },
      { id: 'open', area: PALETTE_AREA, data: { id: 'second-key.open', label: 'Open Approvals', keywords: ['second key', 'approvals', 'ledger'], run: () => host.navigate('/second-key') } }
    ])
  }
}
