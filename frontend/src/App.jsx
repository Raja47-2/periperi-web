import { useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity, AlertTriangle, Archive, ArrowRight, Braces, Check, ChevronDown,
  Clock3, Download, FileArchive, FileCode2, Fingerprint, KeyRound, LockKeyhole,
  Menu, Radar, Search, ShieldCheck, Sparkles, UploadCloud, X,
} from 'lucide-react'

const API = '/api'

const RISK_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
const LABELS = {
  ephemeral: 'Ephemeral data', internal: 'Internal data', pii: 'Personal data',
  financial: 'Financial data', high_sensitivity: 'High-sensitivity data',
  small_project: 'Small project', standard_application: 'Standard application',
  legacy_application: 'Legacy application', complex_system: 'Complex system',
}
const RETENTION_YEARS = { ephemeral: 1, internal: 5, pii: 10, financial: 12, high_sensitivity: 20 }
const MIGRATION_YEARS = { small_project: 1, standard_application: 3, legacy_application: 5, complex_system: 7 }

function App() {
  const [scan, setScan] = useState(null)
  const [selected, setSelected] = useState(null)
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [filter, setFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [mobileNav, setMobileNav] = useState(false)
  const [engines, setEngines] = useState(null)
  const [options, setOptions] = useState({
    sensitivity: 'pii', migration_complexity: 'standard_application', threat_timeline: 15,
  })
  const fileInput = useRef(null)

  useEffect(() => {
    const onEscape = (event) => event.key === 'Escape' && setSelected(null)
    window.addEventListener('keydown', onEscape)
    return () => window.removeEventListener('keydown', onEscape)
  }, [])

  useEffect(() => {
    fetch(`${API}/health`).then((response) => response.json()).then((data) => setEngines(data.engines)).catch(() => {})
  }, [])

  const findings = useMemo(() => {
    if (!scan) return []
    return [...scan.findings]
      .filter((item) => filter === 'all' || item.risk === filter)
      .filter((item) => !query || `${item.name} ${item.file} ${item.category}`.toLowerCase().includes(query.toLowerCase()))
      .sort((a, b) => RISK_ORDER[a.risk] - RISK_ORDER[b.risk])
  }, [scan, filter, query])

  function pickFile(nextFile) {
    if (!nextFile) return
    setError('')
    setFile(nextFile)
  }

  async function runScan(kind = 'upload') {
    if (kind === 'upload' && !file) {
      setError('Choose a project ZIP before starting the scan.')
      return
    }
    setLoading(true)
    setError('')
    setScan(null)
    try {
      let response
      if (kind === 'sample') {
        const params = new URLSearchParams(options)
        response = await fetch(`${API}/scan/sample?${params}`, { method: 'POST' })
      } else {
        const body = new FormData()
        body.append('file', file)
        Object.entries(options).forEach(([key, value]) => body.append(key, value))
        response = await fetch(`${API}/scan`, { method: 'POST', body })
      }
      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'The scan could not be completed.')
      setScan(data)
      setFilter('all')
      requestAnimationFrame(() => document.getElementById('results')?.scrollIntoView({ behavior: 'smooth' }))
    } catch (exception) {
      setError(exception.message === 'Failed to fetch' ? 'The ECDAT backend is not reachable. Start the API and try again.' : exception.message)
    } finally {
      setLoading(false)
    }
  }

  async function downloadCbom() {
    const response = await fetch(`${API}/scan/${scan.id}/report`)
    const data = await response.json()
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `${scan.project_name}-cbom.json`
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="ECDAT home">
          <span className="brand-mark"><Fingerprint size={20} /></span>
          <span>ECDAT</span>
          <span className="brand-tag">CRYPTOGRAPHIC INTELLIGENCE</span>
        </a>
        <nav className={mobileNav ? 'nav-links open' : 'nav-links'}>
          <a href="#scanner" onClick={() => setMobileNav(false)}>Scanner</a>
          <a href="#results" onClick={() => setMobileNav(false)}>Findings</a>
          <a href="#method" onClick={() => setMobileNav(false)}>Methodology</a>
        </nav>
        <button className="menu-button" onClick={() => setMobileNav(!mobileNav)} aria-label="Toggle menu">
          {mobileNav ? <X /> : <Menu />}
        </button>
        <div className="system-status"><span /> {engines?.syft?.available && engines?.trivy?.available ? 'OpenSSL · Syft · Trivy ready' : 'OpenSSL engine ready'}</div>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero-copy">
            <div className="eyebrow"><Sparkles size={14} /> CRYPTOGRAPHIC POSTURE, MADE VISIBLE</div>
            <h1>Find the cryptography<br />you <em>didn’t know</em> you had.</h1>
            <p>Scan source repositories, binaries and container images. Discover algorithms, keys, certificates and crypto libraries, then assess current and quantum risk.</p>
            <div className="hero-actions">
              <a className="button primary" href="#scanner">Start a scan <ArrowRight size={17} /></a>
              <button className="text-button" onClick={() => runScan('sample')}>Explore sample project</button>
            </div>
            <div className="trust-row">
              <span><Check size={14} /> Local analysis</span>
              <span><Check size={14} /> Secret-safe evidence</span>
              <span><Check size={14} /> Explainable rules</span>
            </div>
          </div>
          <div className="hero-visual" aria-hidden="true">
            <div className="orbit orbit-one" />
            <div className="orbit orbit-two" />
            <div className="radar-grid" />
            <div className="visual-core"><Radar size={35} /><span>SCANNING</span></div>
            <div className="signal s1"><span className="risk-dot high" /> RSA-2048 <small>auth.py</small></div>
            <div className="signal s2"><span className="risk-dot low" /> AES-256-GCM <small>vault.py</small></div>
            <div className="signal s3"><span className="risk-dot critical" /> Private key <small>server.pem</small></div>
            <div className="signal s4"><span className="risk-dot medium" /> Certificate <small>api.crt</small></div>
          </div>
        </section>

        <section className="scanner-section" id="scanner">
          <div className="section-heading">
            <div>
              <span className="section-number">01 / DISCOVER</span>
              <h2>Scan a software project</h2>
            </div>
            <p>Files stay on this machine. Uploaded archives are extracted into a temporary directory, scanned, and removed.</p>
          </div>

          <div className="scan-layout">
            <div
              className={`dropzone ${dragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
              onDragOver={(event) => { event.preventDefault(); setDragging(true) }}
              onDragLeave={() => setDragging(false)}
              onDrop={(event) => { event.preventDefault(); setDragging(false); pickFile(event.dataTransfer.files[0]) }}
            >
              <input ref={fileInput} type="file" accept=".zip,.tar,.tar.gz,.tgz,.exe,.dll,.so,.dylib,.jar,.war,.apk,.pem,.crt,.cer,.der,.key,.p12,.pfx" hidden onChange={(event) => pickFile(event.target.files[0])} />
              {file ? (
                <>
                  <div className="upload-icon file-ready"><FileArchive /></div>
                  <strong>{file.name}</strong>
                  <span>{(file.size / 1024 / 1024).toFixed(2)} MB · Ready to analyze</span>
                  <button className="change-file" onClick={() => fileInput.current?.click()}>Choose another file</button>
                </>
              ) : (
                <>
                  <div className="upload-icon"><UploadCloud /></div>
                  <strong>Drop a repository, container, binary or crypto file here</strong>
                  <span>ZIP/TAR, container archive, binary, certificate or key · up to 100 MB</span>
                  <button className="button secondary" onClick={() => fileInput.current?.click()}>Choose project</button>
                </>
              )}
            </div>

            <div className="assumptions-card">
              <div className="card-title"><Clock3 size={18} /> Quantum-risk assumptions</div>
              <label>
                Data sensitivity
                <span className="select-wrap">
                  <select value={options.sensitivity} onChange={(e) => setOptions({ ...options, sensitivity: e.target.value })}>
                    {['ephemeral', 'internal', 'pii', 'financial', 'high_sensitivity'].map((value) => <option key={value} value={value}>{LABELS[value]}</option>)}
                  </select><ChevronDown size={15} />
                </span>
              </label>
              <label>
                Migration complexity
                <span className="select-wrap">
                  <select value={options.migration_complexity} onChange={(e) => setOptions({ ...options, migration_complexity: e.target.value })}>
                    {['small_project', 'standard_application', 'legacy_application', 'complex_system'].map((value) => <option key={value} value={value}>{LABELS[value]}</option>)}
                  </select><ChevronDown size={15} />
                </span>
              </label>
              <label>
                Estimated quantum threat timeline <b>{options.threat_timeline} years</b>
                <input type="range" min="5" max="30" value={options.threat_timeline} onChange={(e) => setOptions({ ...options, threat_timeline: e.target.value })} />
              </label>
              <div className="formula"><span>Exposure</span><b>X + Y &gt; Z</b><small>Prototype Mosca inequality</small></div>
            </div>
          </div>
          {error && <div className="error-banner"><AlertTriangle size={17} /> {error}</div>}
          <div className="scan-actions">
            <button className="button primary large" disabled={loading} onClick={() => runScan('upload')}>
              {loading ? <><span className="spinner" /> Analyzing project…</> : <><Radar size={18} /> Start cryptographic scan</>}
            </button>
            <span>or</span>
            <button className="text-button" disabled={loading} onClick={() => runScan('sample')}>run the built-in demo</button>
          </div>
        </section>

        {loading && <ScanProgress />}
        {scan && <Results scan={scan} findings={findings} filter={filter} setFilter={setFilter} query={query} setQuery={setQuery} setSelected={setSelected} downloadCbom={downloadCbom} />}

        <section className="method-section" id="method">
          <div className="section-heading compact">
            <div><span className="section-number">03 / UNDERSTAND</span><h2>Transparent by design</h2></div>
          </div>
          <div className="method-grid">
            <Method icon={<FileCode2 />} number="01" title="Multi-surface discovery" text="Source rules, OpenSSL parsing, binary fingerprints, Syft inventory and Trivy analysis cover repositories, artifacts and container images." />
            <Method icon={<ShieldCheck />} number="02" title="Explainable assessment" text="Detects OpenSSL, PyCryptodome, Python cryptography, Node Crypto, Web Crypto, libsodium, Bouncy Castle and PKCS#11/HSM usage." />
            <Method icon={<Braces />} number="03" title="Portable CBOM" text="Export a JSON inventory with safe evidence, recommendations and the assumptions behind quantum-risk results." />
          </div>
          <div className="prototype-note"><Activity size={18} /><p><b>Prototype assessment.</b> Findings support triage and inventory work. Validate them with your security team before making production decisions.</p></div>
        </section>
      </main>

      <footer><div className="brand"><span className="brand-mark"><Fingerprint size={18} /></span><span>ECDAT</span></div><p>Enterprise Cryptographic Discovery & Analysis Tool</p><span>SIH 2026 · PS SIH26164</span></footer>
      {selected && <FindingDrawer finding={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

function ScanProgress() {
  return <section className="scan-progress"><div className="progress-copy"><span className="spinner large" /><div><b>Mapping cryptographic dependencies</b><span>Reading supported files and applying security rules…</span></div></div><div className="progress-track"><span /></div></section>
}

function Results({ scan, findings, filter, setFilter, query, setQuery, setSelected, downloadCbom }) {
  const s = scan.summary
  const categories = Object.entries(s.category_distribution).sort((a, b) => b[1] - a[1])
  return (
    <section className="results-section" id="results">
      <div className="results-header">
        <div><span className="section-number">02 / ASSESS</span><h2>{scan.project_name}</h2><p>{(scan.input_type || 'project-directory').replaceAll('-', ' ')} · Scan completed · {new Date(scan.created_at).toLocaleString()}</p></div>
        <button className="button secondary" onClick={downloadCbom}><Download size={17} /> Export CBOM</button>
      </div>
      <div className="metrics-grid">
        <Metric label="Files analyzed" value={s.files_scanned} detail={`${s.files_skipped} skipped`} icon={<FileCode2 />} />
        <Metric label="Crypto findings" value={s.findings} detail={`${Object.keys(s.category_distribution).length} categories`} icon={<Fingerprint />} />
        <Metric label="Urgent findings" value={s.critical + s.high} detail={`${s.critical} critical · ${s.high} high`} icon={<AlertTriangle />} tone="danger" />
        <Metric label="Quantum exposed" value={(s.quantum_distribution.critical || 0) + (s.quantum_distribution.high || 0)} detail="public-key findings" icon={<Radar />} tone="accent" />
      </div>

      <div className="insight-grid">
        <div className="chart-card">
          <div className="card-title">Risk distribution <span>{s.findings} total</span></div>
          <div className="risk-bars">
            {['critical', 'high', 'medium', 'low', 'info'].map((risk) => {
              const count = s.risk_distribution[risk] || 0
              return <div className="bar-row" key={risk}><span>{risk}</span><div><i className={`bar ${risk}`} style={{ width: `${s.findings ? Math.max((count / s.findings) * 100, count ? 5 : 0) : 0}%` }} /></div><b>{count}</b></div>
            })}
          </div>
        </div>
        <div className="chart-card">
          <div className="card-title">Inventory composition <span>by category</span></div>
          <div className="category-list">
            {categories.map(([name, count], index) => <div key={name}><span className={`category-icon c${index}`}><CategoryIcon name={name} /></span><span><b>{name === 'hsm' ? 'HSM' : name}</b><small>{count} detection{count !== 1 ? 's' : ''}</small></span><strong>{Math.round(count / s.findings * 100)}%</strong></div>)}
          </div>
        </div>
        <div className="quantum-card">
          <div className="quantum-head"><Radar /><span><b>Mosca margin</b><small>Selected scenario</small></span></div>
          <div className="equation"><span><b>{RETENTION_YEARS[scan.assumptions.sensitivity]}</b><small>data lifetime</small></span><i>+</i><span><b>{MIGRATION_YEARS[scan.assumptions.migration_complexity]}</b><small>migration</small></span><i>vs</i><span><b>{scan.assumptions.threat_timeline}</b><small>threat timeline</small></span></div>
          <p>Applied only to public-key cryptography affected by Shor’s algorithm.</p>
        </div>
      </div>

      <div className="findings-panel">
        <div className="findings-toolbar">
          <div><h3>Findings</h3><span>{findings.length} shown</span></div>
          <div className="toolbar-controls">
            <div className="search-box"><Search size={16} /><input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search findings" /></div>
            <div className="filter-tabs">{['all', 'critical', 'high', 'medium', 'low'].map((value) => <button key={value} className={filter === value ? 'active' : ''} onClick={() => setFilter(value)}>{value}</button>)}</div>
          </div>
        </div>
        <div className="findings-table">
          <div className="table-head"><span>Finding</span><span>Location</span><span>Risk</span><span>Quantum</span><span /></div>
          {findings.map((finding) => <button className="finding-row" key={finding.id} onClick={() => setSelected(finding)}>
            <span className="finding-name"><CategoryIcon name={finding.category.toLowerCase()} /><span><b>{finding.name}</b><small>{finding.category}</small></span></span>
            <span className="file-location"><b>{finding.file}</b><small>{finding.line ? `Line ${finding.line}` : 'File signal'}</small></span>
            <span><RiskBadge value={finding.risk} /></span>
            <span><RiskBadge value={finding.quantum_risk} muted={finding.quantum_risk === 'not_applicable'} /></span>
            <ArrowRight size={17} />
          </button>)}
          {!findings.length && <div className="empty-state">No findings match this filter.</div>}
        </div>
      </div>
    </section>
  )
}

function FindingDrawer({ finding, onClose }) {
  const q = finding.quantum
  return <div className="drawer-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
    <aside className="drawer">
      <button className="drawer-close" onClick={onClose}><X /></button>
      <span className="drawer-id">{finding.id} · {finding.category}</span>
      <h2>{finding.name}</h2>
      <div className="drawer-badges"><RiskBadge value={finding.risk} /><RiskBadge value={finding.quantum_risk} muted={finding.quantum_risk === 'not_applicable'} /></div>
      <div className="location-card"><FileCode2 /><div><small>Detected in</small><b>{finding.file}</b><span>Line {finding.line}</span></div></div>
      <div className="drawer-section"><h3>Safe evidence</h3><code>{finding.evidence}</code></div>
      <div className="drawer-section"><h3>Why it matters</h3><p>{finding.reason}</p></div>
      {q.margin !== null && <div className="drawer-section"><h3>Quantum timeline</h3><div className="timeline-values"><span><b>{q.x}</b><small>X · Retention</small></span><i>+</i><span><b>{q.y}</b><small>Y · Migration</small></span><i>vs</i><span><b>{q.z}</b><small>Z · Threat</small></span></div><p>{q.reason}</p></div>}
      <div className="recommendation"><ShieldCheck /><div><h3>Recommended action</h3><p>{finding.recommendation}</p></div></div>
      <div className="drawer-disclaimer">Assessment based on explicit prototype rules and selected assumptions.</div>
    </aside>
  </div>
}

function Metric({ label, value, detail, icon, tone = '' }) { return <div className={`metric-card ${tone}`}><div>{icon}<span>{label}</span></div><strong>{value}</strong><small>{detail}</small></div> }
function RiskBadge({ value, muted }) { return <span className={`risk-badge ${muted ? 'muted' : value}`}><i />{value.replace('_', ' ')}</span> }
function CategoryIcon({ name }) { const n = name.toLowerCase(); if (n.includes('key')) return <KeyRound />; if (n.includes('certificate')) return <Archive />; if (n.includes('algorithm')) return <Braces />; if (n.includes('hsm')) return <LockKeyhole />; return <FileCode2 /> }
function Method({ icon, number, title, text }) { return <article className="method-card"><span className="method-icon">{icon}</span><small>{number}</small><h3>{title}</h3><p>{text}</p></article> }

export default App
