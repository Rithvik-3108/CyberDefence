import React, { useState, useMemo, useEffect, useCallback } from 'react';
import axios from 'axios';
import './App1.css';

const API_URL = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/+$/, '');
const API_HOST = API_URL.replace(/^https?:\/\//, '');
const MAX_UPLOAD_MB = Number(import.meta.env.VITE_MAX_UPLOAD_MB || 30);
const PAGE_SIZES = [10, 25, 50, 100];
const SEV_RANK = { high: 3, medium: 2, low: 1 };

const DATASETS = [
  { value: 'cicids2017', label: 'CICIDS2017 (Network Flows)' },
  { value: 'nsl_kdd', label: 'NSL-KDD (Signatures)' },
  { value: 'unsw_nb15', label: 'UNSW-NB15 (Modern Threats)' },
];

const MODELS = [
  { value: 'fcnn', label: 'FCNN (Deep Neural Net)' },
  { value: 'cnn', label: '1D-CNN (Spatial Extraction)' },
  { value: 'lstm', label: 'LSTM (Temporal Sequence)' },
  { value: 'random_forest', label: 'Random Forest' },
  { value: 'decision_tree', label: 'Decision Tree' },
  { value: 'svm', label: 'Support Vector Machine' },
  { value: 'knn', label: 'K-Nearest Neighbors' },
  { value: 'naive_bayes', label: 'Naive Bayes' },
];

const DATASET_SHORT = { cicids2017: 'CICIDS2017', nsl_kdd: 'NSL-KDD', unsw_nb15: 'UNSW-NB15' };
const MODEL_SHORT = {
  fcnn: 'FCNN', cnn: '1D-CNN', lstm: 'LSTM', random_forest: 'Random Forest',
  decision_tree: 'Decision Tree', svm: 'SVM', knn: 'KNN', naive_bayes: 'Naive Bayes',
};
const TABS = [
  ['feed', 'Threat feed'],
  ['analytics', 'Analytics'],
  ['compare', 'Model comparison'],
  ['history', 'Scan history'],
];

/* ---------- helpers ---------- */
const num = (n) => Number(n ?? 0).toLocaleString();

const formatBytes = (b) =>
  b < 1024 * 1024 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1024 / 1024).toFixed(1)} MB`;

const isNil = (v) => v === null || v === undefined || v === '';

function compareValues(a, b) {
  if (isNil(a) || isNil(b)) return isNil(a) === isNil(b) ? 0 : isNil(a) ? -1 : 1;
  const x = Number(a);
  const y = Number(b);
  if (!Number.isNaN(x) && !Number.isNaN(y)) return x - y;
  return String(a).localeCompare(String(b));
}

function csvCell(v) {
  if (v === null || v === undefined) return '';
  let s = String(v);
  // Log text can be attacker-controlled: stop spreadsheets from running it as a formula
  if (typeof v === 'string' && /^[=+\-@]/.test(v) && Number.isNaN(Number(v))) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function downloadText(filename, text, mime) {
  const url = URL.createObjectURL(new Blob([text], { type: mime }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function toTimestamp(v) {
  if (isNil(v)) return NaN;
  if (typeof v === 'number') return v >= 1e11 ? v : v >= 1e9 ? v * 1000 : NaN; // epoch ms / s
  return Date.parse(String(v));
}

function buildTimeline(threats, cols, bins = 24) {
  for (const col of cols.filter((c) => /time|date|stamp/i.test(c))) {
    const stamps = [];
    for (const t of threats) {
      const ts = toTimestamp(t.data[col]);
      if (!Number.isNaN(ts)) stamps.push(ts);
    }
    if (stamps.length < 2 || stamps.length < threats.length * 0.8) continue;
    let min = Infinity;
    let max = -Infinity;
    for (const ts of stamps) {
      if (ts < min) min = ts;
      if (ts > max) max = ts;
    }
    if (min === max) continue;
    const counts = new Array(bins).fill(0);
    for (const ts of stamps) {
      counts[Math.min(bins - 1, Math.floor(((ts - min) / (max - min)) * bins))] += 1;
    }
    return { col, min, max, counts };
  }
  return null;
}

function findCategoricalCols(threats, cols) {
  const sample = threats.slice(0, 5000);
  return cols.filter((c) => {
    if (c === 'predicted_status') return false;
    const seen = new Set();
    for (const t of sample) seen.add(String(t.data[c]));
    if (sample.length > 1 && seen.size < 2) return false; // a constant column says nothing
    if (sample.length >= 3 && seen.size === sample.length) return false; // looks like an ID
    return seen.size <= 25 || seen.size <= sample.length * 0.5; // includes repeated ports and IPs
  });
}

function parseCsvLine(line) {
  const out = [];
  let cur = '';
  let quoted = false;
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (quoted) {
      if (ch === '"') {
        if (line[i + 1] === '"') {
          cur += '"';
          i += 1;
        } else quoted = false;
      } else cur += ch;
    } else if (ch === '"') quoted = true;
    else if (ch === ',') {
      out.push(cur);
      cur = '';
    } else cur += ch;
  }
  out.push(cur);
  return out;
}

async function readCsvHeader(file) {
  const text = await file.slice(0, 256 * 1024).text();
  return parseCsvLine(text.replace(/^\uFEFF/, '').split(/\r?\n/)[0]).map((c) => c.trim());
}

function errorMessage(err) {
  const detail = err.response?.data?.detail;
  if (typeof detail === 'string') return detail;
  if (err.response?.status === 413) return 'The file is too large for the server.';
  if (err.response) return 'The server rejected this request. Check the dataset, model and CSV file.';
  if (err.code === 'ECONNABORTED') return 'The request timed out. The server may be starting up, so try again in a minute.';
  return `Could not reach the backend at ${API_HOST}. If it is on a free plan it may still be waking up, so wait a minute and retry.`;
}

function topCounts(threats, col, n = 8) {
  const m = new Map();
  threats.forEach((t) => {
    const k = String(t.data[col]);
    m.set(k, (m.get(k) || 0) + 1);
  });
  return [...m.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([label, value]) => ({ label, value }));
}

/* ---------- small presentational pieces ---------- */
function SeverityBadge({ severity }) {
  if (!severity) return <span className="badge-threat">Threat detected</span>;
  return <span className={`sev sev--${severity}`}>{severity}</span>;
}

function SortHeader({ k, label, sortKey, sortDir, onSort }) {
  const active = sortKey === k;
  return (
    <th aria-sort={active ? (sortDir === 'asc' ? 'ascending' : 'descending') : 'none'}>
      <button type="button" className="th-btn" onClick={() => onSort(k)}>
        <span>{label}</span>
        <span className="th-arrow" aria-hidden="true">
          {active ? (sortDir === 'asc' ? '▲' : '▼') : '↕'}
        </span>
      </button>
    </th>
  );
}

function BarList({ items }) {
  const max = Math.max(1, ...items.map((i) => i.value));
  return (
    <ul className="bars">
      {items.map((i) => (
        <li key={i.label}>
          <span className="bar-label" title={i.label}>{i.label}</span>
          <span className="bar-track">
            <span
              className="bar-fill"
              style={{ width: `${(i.value / max) * 100}%`, ...(i.color ? { '--bar': i.color } : {}) }}
            />
          </span>
          <span className="bar-value">{num(i.value)}</span>
        </li>
      ))}
    </ul>
  );
}

function MetricsPanel({ metrics }) {
  const pct = (v) => `${(v * 100).toFixed(2)}%`;
  const cm = metrics.confusion_matrix;
  return (
    <>
      <div className="metric-grid">
        {[['Accuracy', metrics.accuracy], ['Precision', metrics.precision], ['Recall', metrics.recall], ['F1 score', metrics.f1]].map(
          ([label, v]) => (
            <div className="metric" key={label}>
              <span className="metric-label">{label}</span>
              <strong className="metric-value">{pct(v)}</strong>
            </div>
          )
        )}
      </div>
      <div className="cm" role="group" aria-label="Confusion matrix">
        <span />
        <span className="cm-head">Predicted normal</span>
        <span className="cm-head">Predicted attack</span>
        <span className="cm-head">Actual normal</span>
        <span className="cm-cell cm-cell--ok">{num(cm.tn)}<small>true negatives</small></span>
        <span className="cm-cell cm-cell--bad">{num(cm.fp)}<small>false alarms</small></span>
        <span className="cm-head">Actual attack</span>
        <span className="cm-cell cm-cell--bad">{num(cm.fn)}<small>missed attacks</small></span>
        <span className="cm-cell cm-cell--ok">{num(cm.tp)}<small>true positives</small></span>
      </div>
      <p className="note">
        Calculated on {num(metrics.labelled_records)} rows using the &quot;{metrics.label_column}&quot; column.
        Values other than 0, normal or benign count as attacks.
      </p>
    </>
  );
}

function CompareTable({ data }) {
  const ag = data.agreement;
  const hasF1 = data.models.some((m) => m.metrics);
  return (
    <>
      <div className="run-info">
        <span className="tag">{DATASET_SHORT[data.dataset] || data.dataset}</span>
        <span className="tag">{data.file}</span>
        <span className="tag">{num(data.total_records)} records</span>
      </div>
      {ag && (
        <div className="agree">
          <div className="agree-bar" role="img" aria-label="How many records the models agree on">
            <span className="agree-seg agree-seg--threat" style={{ flexGrow: ag.unanimous_threat }} />
            <span className="agree-seg agree-seg--split" style={{ flexGrow: ag.split }} />
            <span className="agree-seg agree-seg--normal" style={{ flexGrow: ag.unanimous_normal }} />
          </div>
          <ul className="agree-legend">
            <li><i className="dot dot--threat" />All {ag.models_compared} flag a threat: {num(ag.unanimous_threat)}</li>
            <li><i className="dot dot--split" />Models disagree: {num(ag.split)}</li>
            <li><i className="dot dot--normal" />All see normal: {num(ag.unanimous_normal)}</li>
          </ul>
        </div>
      )}
      <div className="table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>Model</th>
              <th className="is-num">Threats</th>
              <th className="is-num">Threat rate</th>
              <th className="is-num">Time</th>
              {hasF1 && <th className="is-num">F1 score</th>}
              <th className="is-num">Agrees with majority</th>
            </tr>
          </thead>
          <tbody>
            {data.models.map((m) =>
              m.status === 'ok' ? (
                <tr key={m.model}>
                  <td>{MODEL_SHORT[m.model] || m.model}</td>
                  <td className="is-num">{num(m.threats)}</td>
                  <td className="is-num">{m.threat_rate}%</td>
                  <td className="is-num">{m.seconds}s</td>
                  {hasF1 && <td className="is-num">{m.metrics ? `${(m.metrics.f1 * 100).toFixed(2)}%` : '-'}</td>}
                  <td className="is-num">{m.agrees_with_majority != null ? `${m.agrees_with_majority}%` : '-'}</td>
                </tr>
              ) : (
                <tr key={m.model}>
                  <td>{MODEL_SHORT[m.model] || m.model}</td>
                  <td className="is-error" colSpan={hasF1 ? 5 : 4}>Could not run: {m.detail}</td>
                </tr>
              )
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

function HistoryTable({ history }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Dataset</th>
            <th>Model</th>
            <th>File</th>
            <th className="is-num">Records</th>
            <th className="is-num">Threats</th>
            <th className="is-num">Rate</th>
          </tr>
        </thead>
        <tbody>
          {history.map((h) => (
            <tr key={h.id}>
              <td>{h.at.toLocaleTimeString()}</td>
              <td>{DATASET_SHORT[h.dataset]}</td>
              <td>{MODEL_SHORT[h.model]}</td>
              <td className="cell-file" title={h.fileName}>{h.fileName}</td>
              <td className="is-num">{num(h.total)}</td>
              <td className="is-num">{num(h.threats)}</td>
              <td className="is-num">{h.rate.toFixed(1)}%</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/* ---------- main app ---------- */
export default function App() {
  const [dataset, setDataset] = useState('cicids2017');
  const [modelType, setModelType] = useState('fcnn');
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploadPct, setUploadPct] = useState(null);
  const [result, setResult] = useState(null);
  const [lastRun, setLastRun] = useState(null);
  const [error, setError] = useState(null);
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [toast, setToast] = useState(null);
  const [engine, setEngine] = useState('checking');
  const [tab, setTab] = useState('feed');
  const [sortKey, setSortKey] = useState('@score');
  const [sortDir, setSortDir] = useState('desc');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [visibleCols, setVisibleCols] = useState(null);
  const [showColMenu, setShowColMenu] = useState(false);
  const [catCol, setCatCol] = useState(null);
  const [compareResult, setCompareResult] = useState(null);
  const [comparing, setComparing] = useState(false);
  const [compareError, setCompareError] = useState(null);
  const [history, setHistory] = useState([]);
  const [sevFilter, setSevFilter] = useState('all');
  const [schemaCheck, setSchemaCheck] = useState(null);

  const notify = (msg) => {
    setToast(msg);
    setTimeout(() => setToast(null), 3500);
  };

  // Real backend status. The long timeout covers free-tier cold starts (30-60 s).
  const checkEngine = useCallback(() => {
    setEngine('checking');
    axios
      .get(`${API_URL}/health`, { timeout: 70000 })
      .then(() => setEngine('online'))
      .catch((err) => setEngine(err.response ? 'online' : 'offline'));
  }, []);

  useEffect(() => {
    checkEngine();
  }, [checkEngine]);

  // Escape closes the inspector and the column menu
  useEffect(() => {
    if (!selectedThreat && !showColMenu) return undefined;
    const onKey = (e) => {
      if (e.key === 'Escape') {
        setSelectedThreat(null);
        setShowColMenu(false);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [selectedThreat, showColMenu]);

  // Compare the CSV header with the columns the chosen dataset's model needs
  useEffect(() => {
    if (!file) {
      setSchemaCheck(null);
      return undefined;
    }
    let cancelled = false;
    (async () => {
      try {
        const [{ data }, header] = await Promise.all([
          axios.get(`${API_URL}/schema/${dataset}`, { timeout: 90000 }),
          readCsvHeader(file),
        ]);
        if (cancelled) return;
        const have = new Set(header);
        setSchemaCheck({
          dataset,
          required: data.required_columns.length,
          missing: data.required_columns.filter((c) => !have.has(c)),
        });
      } catch {
        if (!cancelled) setSchemaCheck(null); // older backend or unreadable file: skip the check
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [file, dataset]);

  const handleFile = (e) => {
    const f = e.target.files[0];
    if (!f) return;
    if (!f.name.toLowerCase().endsWith('.csv')) {
      setError('Only .csv files are supported. Export your security logs as CSV and try again.');
      return;
    }
    if (f.size > MAX_UPLOAD_MB * 1024 * 1024) {
      setError(`This file is ${formatBytes(f.size)}. The upload limit is ${MAX_UPLOAD_MB} MB.`);
      return;
    }
    setError(null);
    setFile(f);
    setCompareResult(null);
    setCompareError(null);
  };

  const handleScan = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please upload a valid security log CSV file.');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    setSelectedThreat(null);
    setUploadPct(0);

    const formData = new FormData();
    formData.append('dataset', dataset);
    formData.append('model_type', modelType);
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_URL}/predict`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 600000,
        onUploadProgress: (ev) => {
          if (ev.total) setUploadPct(Math.round((ev.loaded / ev.total) * 100));
        },
      });
      const data = response.data;
      const hasScores = Array.isArray(data.threat_meta) && data.threat_meta.length > 0;

      setResult(data);
      setSearchTerm('');
      setSevFilter('all');
      setPage(1);
      setVisibleCols(null);
      setCatCol(null);
      setSortKey(hasScores ? '@score' : '@row');
      setSortDir(hasScores ? 'desc' : 'asc');
      setLastRun({ dataset, model: modelType, fileName: file.name });
      setHistory((h) =>
        [
          {
            id: Date.now(),
            at: new Date(),
            dataset,
            model: modelType,
            fileName: file.name,
            total: data.summary.total_records,
            threats: data.summary.detected_threats,
            rate: data.summary.total_records > 0
              ? (data.summary.detected_threats / data.summary.total_records) * 100
              : 0,
          },
          ...h,
        ].slice(0, 10)
      );
      setEngine('online');
      notify('Threat telemetry scan completed successfully.');
    } catch (err) {
      setError(errorMessage(err));
      if (!err.response) setEngine('offline');
    } finally {
      setLoading(false);
      setUploadPct(null);
    }
  };

  const handleCompare = async () => {
    if (!file) {
      setCompareError('Upload a CSV log first, then run the comparison.');
      return;
    }
    setComparing(true);
    setCompareError(null);

    const formData = new FormData();
    formData.append('dataset', dataset);
    formData.append('file', file);

    try {
      const response = await axios.post(`${API_URL}/compare`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        timeout: 1200000,
      });
      setCompareResult({ ...response.data, file: file.name });
      notify('Model comparison completed.');
    } catch (err) {
      setCompareError(errorMessage(err));
    } finally {
      setComparing(false);
    }
  };

  /* ----- derived data ----- */
  const threats = useMemo(() => {
    if (!result || !result.threat_details) return [];
    const meta = result.threat_meta || [];
    return result.threat_details.map((data, id) => ({ id, data, meta: meta[id] || null }));
  }, [result]);

  const hasMeta = threats.length > 0 && threats[0].meta !== null;
  const allCols = useMemo(() => (threats.length ? Object.keys(threats[0].data) : []), [threats]);
  const defaultCols = useMemo(
    () => allCols.filter((c) => c !== 'predicted_status').slice(0, 3),
    [allCols]
  );
  const shownCols = visibleCols ? allCols.filter((c) => visibleCols.includes(c)) : defaultCols;

  const filteredThreats = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    return threats.filter((t) => {
      if (sevFilter !== 'all' && t.meta?.severity !== sevFilter) return false;
      if (!q) return true;
      return (
        Object.values(t.data).some((val) => String(val).toLowerCase().includes(q)) ||
        Boolean(t.meta && t.meta.severity.includes(q))
      );
    });
  }, [threats, searchTerm, sevFilter]);

  const sortedThreats = useMemo(() => {
    const dir = sortDir === 'asc' ? 1 : -1;
    return [...filteredThreats].sort((a, b) => {
      let r;
      if (sortKey === '@row') r = a.id - b.id;
      else if (sortKey === '@score') r = compareValues(a.meta?.score, b.meta?.score);
      else if (sortKey === '@severity') {
        r = (SEV_RANK[a.meta?.severity] || 0) - (SEV_RANK[b.meta?.severity] || 0)
          || compareValues(a.meta?.score, b.meta?.score);
      } else r = compareValues(a.data[sortKey], b.data[sortKey]);
      return r * dir;
    });
  }, [filteredThreats, sortKey, sortDir]);

  const pageCount = Math.max(1, Math.ceil(sortedThreats.length / pageSize));
  const safePage = Math.min(page, pageCount);
  const pageRows = sortedThreats.slice((safePage - 1) * pageSize, safePage * pageSize);
  const rangeStart = sortedThreats.length ? (safePage - 1) * pageSize + 1 : 0;
  const rangeEnd = Math.min(safePage * pageSize, sortedThreats.length);

  const threatRate = useMemo(() => {
    if (!result || !result.summary) return 0;
    const total = Number(result.summary.total_records);
    const flagged = Number(result.summary.detected_threats);
    return total > 0 ? Math.min(100, (flagged / total) * 100) : 0;
  }, [result]);

  const analytics = useMemo(() => {
    if (!threats.length) return null;
    const sev = { high: 0, medium: 0, low: 0 };
    threats.forEach((t) => {
      if (t.meta && t.meta.severity in sev) sev[t.meta.severity] += 1;
    });
    return {
      sev,
      hasSev: sev.high + sev.medium + sev.low > 0,
      catCols: findCategoricalCols(threats, allCols),
      timeline: buildTimeline(threats, allCols),
    };
  }, [threats, allCols]);

  const truncated = Boolean(result?.summary?.threats_truncated);
  const sevTotals = result?.summary?.severity_counts || (analytics ? analytics.sev : null);
  const catCols = analytics ? analytics.catCols : [];
  const activeCat =
    catCol && catCols.includes(catCol)
      ? catCol
      : catCols.find((c) => /attack|cat|proto|service|label|port|\bip\b|addr/i.test(c)) || catCols[0] || null;
  const topList = useMemo(() => (activeCat ? topCounts(threats, activeCat) : []), [threats, activeCat]);

  /* ----- handlers ----- */
  const onSort = (key) => {
    setPage(1);
    if (key === sortKey) setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    else {
      setSortKey(key);
      setSortDir(key === '@score' || key === '@severity' ? 'desc' : 'asc');
    }
  };

  const toggleCol = (c) =>
    setVisibleCols((cur) => {
      const base = cur || defaultCols;
      return base.includes(c) ? base.filter((x) => x !== c) : [...base, c];
    });

  const exportRows = () =>
    sortedThreats.map(({ id, data, meta }) => ({
      row: id + 1,
      ...(meta ? { severity: meta.severity, threat_score: meta.score } : {}),
      ...data,
    }));

  const exportName = () => {
    const stamp = new Date().toISOString().slice(0, 16).replace(/[-:T]/g, '');
    const run = lastRun || { dataset, model: modelType };
    return `ai-siem-threats-${run.dataset}-${run.model}-${stamp}`;
  };

  const exportCsv = () => {
    const rows = exportRows();
    if (!rows.length) return;
    const cols = Object.keys(rows[0]);
    const text = [cols.map(csvCell).join(','), ...rows.map((r) => cols.map((c) => csvCell(r[c])).join(','))].join('\n');
    downloadText(`${exportName()}.csv`, text, 'text/csv;charset=utf-8');
    notify(`Exported ${num(rows.length)} threats as CSV.`);
  };

  const exportJson = () => {
    const rows = exportRows();
    if (!rows.length) return;
    downloadText(`${exportName()}.json`, JSON.stringify(rows, null, 2), 'application/json');
    notify(`Exported ${num(rows.length)} threats as JSON.`);
  };

  const handleRowKey = (e, threat) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      setSelectedThreat(threat);
    }
  };

  const busy = loading || comparing;
  const engineText = {
    checking: 'Waking up engine...',
    online: 'Detection engine online',
    offline: 'Backend offline',
  }[engine];
  const sortProps = { sortKey, sortDir, onSort };

  return (
    <div className="siem">
      {/* TOAST */}
      {toast && (
        <div className="toast" role="status" aria-live="polite">
          <span className="toast-dot" />
          <span>
            <strong>AI-SIEM:</strong> {toast}
          </span>
        </div>
      )}

      {/* HEADER */}
      <header className="siem-header">
        <div className="brand">
          <svg className="brand-logo" viewBox="0 0 32 32" aria-hidden="true">
            <path d="M16 3l11 4v8c0 7-4.6 12.3-11 14C9.6 27.3 5 22 5 15V7z" />
            <path d="M11 16l3.5 3.5L21 12.5" />
          </svg>
          <div>
            <h1 className="brand-title">AI-SIEM</h1>
            <p className="brand-tagline">
              AI-driven Security Information and Event Management for intrusion detection
            </p>
          </div>
        </div>
        <div className={`engine-status ${busy ? 'is-busy' : `is-${engine}`}`}>
          <span className="engine-dot" />
          <span>{busy ? 'Analyzing logs' : engineText}</span>
          {!busy && engine === 'offline' && (
            <button type="button" className="link-btn" onClick={checkEngine}>Retry</button>
          )}
        </div>
      </header>

      <main className="layout">
        {/* LEFT: SCAN CONTROLS */}
        <section className="panel controls" aria-labelledby="controls-title">
          <div className="panel-head">
            <h2 className="panel-title" id="controls-title">Scan setup</h2>
            <span className="tag">v3.0</span>
          </div>

          <form onSubmit={handleScan} className="scan-form">
            <div>
              <label className="field-label" htmlFor="dataset">Target dataset</label>
              <select id="dataset" className="field-input" value={dataset} onChange={(e) => setDataset(e.target.value)}>
                {DATASETS.map((d) => (
                  <option key={d.value} value={d.value}>{d.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="field-label" htmlFor="model">Detection model</label>
              <select id="model" className="field-input" value={modelType} onChange={(e) => setModelType(e.target.value)}>
                {MODELS.map((m) => (
                  <option key={m.value} value={m.value}>{m.label}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="field-label" htmlFor="logs">Security logs (CSV)</label>
              <div className={`dropzone ${file ? 'has-file' : ''}`}>
                <input id="logs" type="file" accept=".csv,text/csv,application/vnd.ms-excel" className="dropzone-input" onChange={handleFile} />
                <svg className="dropzone-icon" viewBox="0 0 24 24" aria-hidden="true">
                  <path d="M12 16V4M7 9l5-5 5 5M4 16v3a1 1 0 001 1h14a1 1 0 001-1v-3" />
                </svg>
                {file ? (
                  <>
                    <span className="dropzone-file">{file.name}</span>
                    <span className="dropzone-meta">{formatBytes(file.size)}</span>
                  </>
                ) : (
                  <span>
                    Drag a CSV log here or <span className="dropzone-link">browse</span>
                    <span className="dropzone-meta">CSV only, up to {MAX_UPLOAD_MB} MB</span>
                  </span>
                )}
              </div>
              {schemaCheck && schemaCheck.dataset === dataset && schemaCheck.missing.length > 0 && (
                <div className="alert-warn" role="alert">
                  <strong>Columns missing.</strong> This file lacks {schemaCheck.missing.length} of the{' '}
                  {schemaCheck.required} columns the {DATASET_SHORT[dataset]} model needs, such as{' '}
                  {schemaCheck.missing.slice(0, 3).map((c) => `"${c}"`).join(', ')}. Check the dataset
                  selection or the file before scanning.
                </div>
              )}
              {schemaCheck && schemaCheck.dataset === dataset && schemaCheck.missing.length === 0 && (
                <p className="field-ok">All {schemaCheck.required} required columns found.</p>
              )}
            </div>

            <button type="submit" disabled={loading} className="scan-btn">
              {loading && <span className="spinner" aria-hidden="true" />}
              {loading ? 'Analyzing logs...' : 'Run threat scan'}
            </button>
          </form>

          {loading && (
            <div className="progress" aria-live="polite">
              <div className="progress-track">
                <span
                  className={`progress-fill ${uploadPct === 100 ? 'is-indeterminate' : ''}`}
                  style={uploadPct === 100 ? undefined : { width: `${uploadPct || 0}%` }}
                />
              </div>
              <div className="progress-label">
                <span>{uploadPct === 100 ? 'Model is analyzing the logs' : 'Uploading logs'}</span>
                {uploadPct !== 100 && <span>{uploadPct || 0}%</span>}
              </div>
            </div>
          )}

          {error && (
            <div className="alert-error" role="alert">
              <strong>Error:</strong> {error}
            </div>
          )}

          <div className="panel-foot">
            <span>Endpoint</span>
            <span>{API_HOST}</span>
          </div>
        </section>

        {/* RIGHT: SUMMARY + TABS */}
        <div className="results">
          {result && (
            <>
              <div className="stats">
                <div className="stat">
                  <div>
                    <p className="stat-label">Total packets</p>
                    <p className="stat-value">{num(result.summary.total_records)}</p>
                  </div>
                </div>
                <div className="stat stat--green">
                  <div>
                    <p className="stat-label">Normal traffic</p>
                    <p className="stat-value">{num(result.summary.normal_traffic)}</p>
                  </div>
                </div>
                <div className="stat stat--magenta">
                  <div>
                    <p className="stat-label">Threats flagged</p>
                    <p className="stat-value">{num(result.summary.detected_threats)}</p>
                  </div>
                  <div
                    className="ring"
                    style={{ '--pct': threatRate }}
                    role="img"
                    aria-label={`${threatRate.toFixed(1)} percent of records flagged`}
                  >
                    <span className="ring-text">{threatRate.toFixed(1)}%</span>
                  </div>
                </div>
                {result.summary.elapsed_seconds != null && (
                  <div className="stat stat--amber">
                    <div>
                      <p className="stat-label">Scan time</p>
                      <p className="stat-value">{result.summary.elapsed_seconds}s</p>
                    </div>
                  </div>
                )}
              </div>
              {lastRun && (
                <div className="run-info">
                  <span className="tag">{DATASET_SHORT[lastRun.dataset]}</span>
                  <span className="tag">{MODEL_SHORT[lastRun.model]}</span>
                  <span className="tag">{lastRun.fileName}</span>
                </div>
              )}
            </>
          )}

          <section className={`panel feed ${loading ? 'is-scanning' : ''}`}>
            <div className="tabs" role="tablist" aria-label="Dashboard views">
              {TABS.map(([key, label]) => (
                <button
                  key={key}
                  type="button"
                  role="tab"
                  id={`tab-${key}`}
                  aria-selected={tab === key}
                  aria-controls={`panel-${key}`}
                  className="tab"
                  onClick={() => setTab(key)}
                >
                  {label}
                </button>
              ))}
            </div>

            {/* ---------- THREAT FEED ---------- */}
            {tab === 'feed' && (
              <div role="tabpanel" id="panel-feed" aria-labelledby="tab-feed">
                {!result ? (
                  <div className="empty">
                    <strong>{loading ? 'Analyzing your logs...' : 'No scan yet'}</strong>
                    <span>
                      {loading
                        ? 'Detected threats will appear here as soon as the scan finishes.'
                        : 'Choose a dataset and model, upload a CSV log, then run the threat scan.'}
                    </span>
                  </div>
                ) : threats.length === 0 ? (
                  <div className="empty empty--safe">
                    <strong>No threats detected</strong>
                    <span>Zero malicious anomalies were found in this batch.</span>
                  </div>
                ) : (
                  <>
                    {truncated && (
                      <div className="banner" role="note">
                        Showing the {num(result.summary.threats_returned)} highest-scoring threats out of{' '}
                        {num(result.summary.detected_threats)}. Totals and severity counts cover all of them;
                        exports include only the rows shown.
                      </div>
                    )}
                    <div className="toolbar">
                      <div className="toolbar-actions">
                        <span className="tag tag-hot">{num(sortedThreats.length)} flagged</span>
                        <input
                          type="text"
                          className="search-input"
                          placeholder="Filter threats..."
                          aria-label="Filter threats"
                          value={searchTerm}
                          onChange={(e) => {
                            setSearchTerm(e.target.value);
                            setPage(1);
                          }}
                        />
                        {hasMeta && analytics && (
                          <div className="seg-group" role="group" aria-label="Filter by severity">
                            {['all', 'high', 'medium', 'low'].map((level) => (
                              <button
                                key={level}
                                type="button"
                                className={`seg seg--${level} ${sevFilter === level ? 'is-active' : ''}`}
                                aria-pressed={sevFilter === level}
                                onClick={() => {
                                  setSevFilter(level);
                                  setPage(1);
                                }}
                              >
                                {level === 'all' ? 'All' : level}
                                <span className="seg-count">
                                  {level === 'all' ? num(threats.length) : num(analytics.sev[level])}
                                </span>
                              </button>
                            ))}
                          </div>
                        )}
                      </div>
                      <div className="toolbar-actions">
                        <div className="menu-wrap">
                          <button
                            type="button"
                            className="btn-ghost"
                            aria-expanded={showColMenu}
                            onClick={() => setShowColMenu((s) => !s)}
                          >
                            Columns ({shownCols.length})
                          </button>
                          {showColMenu && (
                            <>
                              <div className="menu-scrim" onClick={() => setShowColMenu(false)} />
                              <div className="menu" role="group" aria-label="Choose columns">
                                {allCols.map((c) => (
                                  <label key={c} className="menu-item">
                                    <input type="checkbox" checked={shownCols.includes(c)} onChange={() => toggleCol(c)} />
                                    <span>{c}</span>
                                  </label>
                                ))}
                              </div>
                            </>
                          )}
                        </div>
                        <button type="button" className="btn-ghost" onClick={exportCsv}>Export CSV</button>
                        <button type="button" className="btn-ghost" onClick={exportJson}>Export JSON</button>
                      </div>
                    </div>

                    {sortedThreats.length === 0 ? (
                      <div className="empty">
                        <strong>No matches</strong>
                        <span>No threats match your filter. Try a different keyword.</span>
                      </div>
                    ) : (
                      <>
                        <div className="feed-scroll">
                          <table className="threat-table">
                            <thead>
                              <tr>
                                <SortHeader k="@row" label="Row" {...sortProps} />
                                {hasMeta ? <SortHeader k="@severity" label="Severity" {...sortProps} /> : <th>Status</th>}
                                {hasMeta && <SortHeader k="@score" label="Score" {...sortProps} />}
                                {shownCols.map((c) => (
                                  <SortHeader key={c} k={c} label={c} {...sortProps} />
                                ))}
                                <th className="col-action">Action</th>
                              </tr>
                            </thead>
                            <tbody>
                              {pageRows.map((t) => (
                                <tr
                                  key={t.id}
                                  className="threat-row"
                                  tabIndex={0}
                                  onClick={() => setSelectedThreat(t)}
                                  onKeyDown={(e) => handleRowKey(e, t)}
                                >
                                  <td className="col-index">#{t.id + 1}</td>
                                  <td><SeverityBadge severity={t.meta?.severity} /></td>
                                  {hasMeta && (
                                    <td className="col-score">
                                      <span className="score">
                                        <span className="score-bar"><i style={{ width: `${Math.round(t.meta.score * 100)}%` }} /></span>
                                        {t.meta.score.toFixed(3)}
                                      </span>
                                    </td>
                                  )}
                                  {shownCols.map((c) => (
                                    <td key={c} className="col-attr" data-label={c} title={`${c}: ${t.data[c]}`}>
                                      {t.data[c] === null ? 'null' : String(t.data[c])}
                                    </td>
                                  ))}
                                  <td className="col-action">
                                    <button
                                      type="button"
                                      className="btn-ghost"
                                      onClick={(e) => {
                                        e.stopPropagation();
                                        setSelectedThreat(t);
                                      }}
                                    >
                                      Inspect
                                    </button>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>

                        <div className="pager">
                          <span>
                            {num(rangeStart)}-{num(rangeEnd)} of {num(sortedThreats.length)}
                          </span>
                          <div className="pager-controls">
                            <label htmlFor="page-size">Rows per page</label>
                            <select
                              id="page-size"
                              className="field-input select-sm"
                              value={pageSize}
                              onChange={(e) => {
                                setPageSize(Number(e.target.value));
                                setPage(1);
                              }}
                            >
                              {PAGE_SIZES.map((s) => (
                                <option key={s} value={s}>{s}</option>
                              ))}
                            </select>
                            <button type="button" className="btn-ghost" disabled={safePage <= 1} onClick={() => setPage(safePage - 1)}>
                              Previous
                            </button>
                            <span>Page {safePage} of {pageCount}</span>
                            <button type="button" className="btn-ghost" disabled={safePage >= pageCount} onClick={() => setPage(safePage + 1)}>
                              Next
                            </button>
                          </div>
                        </div>
                      </>
                    )}
                  </>
                )}
              </div>
            )}

            {/* ---------- ANALYTICS ---------- */}
            {tab === 'analytics' && (
              <div role="tabpanel" id="panel-analytics" aria-labelledby="tab-analytics">
                {!result ? (
                  <div className="empty">
                    <strong>No data to chart</strong>
                    <span>Run a threat scan to see charts and evaluation metrics.</span>
                  </div>
                ) : (
                  <div className="analytics">
                    {truncated && (
                      <div className="banner card--wide" role="note">
                        Severity totals and the donut cover all {num(result.summary.detected_threats)} threats.
                        The value and time charts use the {num(result.summary.threats_returned)} highest-scoring ones.
                      </div>
                    )}
                    <div className="card">
                      <h3 className="card-title">Normal vs threat traffic</h3>
                      <div className="donut-wrap">
                        <div className="donut" style={{ '--p': threatRate }} role="img" aria-label={`${threatRate.toFixed(1)} percent flagged`}>
                          <div className="donut-center">
                            <strong>{threatRate.toFixed(1)}%</strong>
                            <span>flagged</span>
                          </div>
                        </div>
                        <ul className="legend">
                          <li><i className="dot dot--threat" />Threats: {num(result.summary.detected_threats)}</li>
                          <li><i className="dot dot--normal" />Normal: {num(result.summary.normal_traffic)}</li>
                        </ul>
                      </div>
                    </div>

                    {analytics && analytics.hasSev && sevTotals && (
                      <div className="card">
                        <h3 className="card-title">Threats by severity</h3>
                        <BarList
                          items={[
                            { label: 'High', value: sevTotals.high, color: 'var(--red)' },
                            { label: 'Medium', value: sevTotals.medium, color: 'var(--amber)' },
                            { label: 'Low', value: sevTotals.low, color: 'var(--cyan)' },
                          ]}
                        />
                      </div>
                    )}

                    {catCols.length > 0 && (
                      <div className="card">
                        <div className="card-head">
                          <h3 className="card-title">Most common values</h3>
                          <select
                            className="field-input select-sm"
                            aria-label="Column to summarize"
                            value={activeCat || ''}
                            onChange={(e) => setCatCol(e.target.value)}
                          >
                            {catCols.map((c) => (
                              <option key={c} value={c}>{c}</option>
                            ))}
                          </select>
                        </div>
                        <BarList items={topList} />
                      </div>
                    )}

                    {analytics && analytics.timeline && (
                      <div className="card card--wide">
                        <h3 className="card-title">Threats over time ({analytics.timeline.col})</h3>
                        <div className="timeline" role="img" aria-label="Threat count over time">
                          {analytics.timeline.counts.map((c, i) => (
                            <span
                              key={i}
                              title={`${c} threats`}
                              style={{ height: `${(c / Math.max(1, ...analytics.timeline.counts)) * 100}%` }}
                            />
                          ))}
                        </div>
                        <div className="timeline-axis">
                          <span>{new Date(analytics.timeline.min).toLocaleString()}</span>
                          <span>{new Date(analytics.timeline.max).toLocaleString()}</span>
                        </div>
                      </div>
                    )}

                    <div className="card card--wide">
                      <h3 className="card-title">Detection accuracy</h3>
                      {result.metrics ? (
                        <MetricsPanel metrics={result.metrics} />
                      ) : (
                        <p className="note">
                          Add a &quot;label&quot; column to your CSV to see accuracy, precision, recall, F1 and a
                          confusion matrix for this scan.
                        </p>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* ---------- MODEL COMPARISON ---------- */}
            {tab === 'compare' && (
              <div role="tabpanel" id="panel-compare" aria-labelledby="tab-compare">
                <div className="toolbar">
                  <p className="note note--flush">
                    Runs your uploaded CSV through all eight models on {DATASET_SHORT[dataset]}.
                    Large files can take a few minutes.
                  </p>
                  <button type="button" className="scan-btn scan-btn--inline" disabled={comparing || loading} onClick={handleCompare}>
                    {comparing && <span className="spinner" aria-hidden="true" />}
                    {comparing ? 'Comparing models...' : 'Compare all models'}
                  </button>
                </div>
                {compareError && (
                  <div className="alert-error" role="alert">
                    <strong>Error:</strong> {compareError}
                  </div>
                )}
                {compareResult ? (
                  <CompareTable data={compareResult} />
                ) : (
                  !compareError && (
                    <div className="empty">
                      <strong>{comparing ? 'Running every model...' : 'No comparison yet'}</strong>
                      <span>
                        {comparing
                          ? 'Results appear here when all models have finished.'
                          : 'Upload a CSV, choose a dataset, then compare all models to see where they agree.'}
                      </span>
                    </div>
                  )
                )}
              </div>
            )}

            {/* ---------- HISTORY ---------- */}
            {tab === 'history' && (
              <div role="tabpanel" id="panel-history" aria-labelledby="tab-history">
                {history.length === 0 ? (
                  <div className="empty">
                    <strong>No scans yet</strong>
                    <span>Your last 10 scans from this session will be listed here for comparison.</span>
                  </div>
                ) : (
                  <>
                    <div className="toolbar">
                      <p className="note note--flush">Scan summaries from this session. Results are not stored.</p>
                      <button type="button" className="btn-ghost" onClick={() => setHistory([])}>Clear history</button>
                    </div>
                    <HistoryTable history={history} />
                  </>
                )}
              </div>
            )}
          </section>
        </div>
      </main>

      {/* INSPECT MODAL */}
      {selectedThreat && (
        <div className="modal-backdrop" onClick={() => setSelectedThreat(null)}>
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="inspector-title"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="modal-head">
              <h3 className="panel-title" id="inspector-title">Packet telemetry inspector</h3>
              <button type="button" className="modal-close" aria-label="Close inspector" onClick={() => setSelectedThreat(null)}>
                &times;
              </button>
            </div>

            <div className="modal-body">
              {selectedThreat.meta && (
                <>
                  <div className="inspect-summary">
                    <SeverityBadge severity={selectedThreat.meta.severity} />
                    <span>Threat score <strong>{selectedThreat.meta.score.toFixed(3)}</strong></span>
                    <span>Similarity to normal traffic <strong>{selectedThreat.meta.similarity_to_normal.toFixed(3)}</strong></span>
                    <span>CSV row <strong>{num(selectedThreat.meta.row)}</strong></span>
                  </div>
                  {selectedThreat.meta.unusual_events.length > 0 && (
                    <div className="inspect-events">
                      <h4>Most unusual events compared with normal traffic</h4>
                      <div className="chips">
                        {selectedThreat.meta.unusual_events.map((ev) => (
                          <span className="chip" key={ev}>
                            <span className="chip-val">{ev}</span>
                          </span>
                        ))}
                      </div>
                      <p>
                        These event bins show up in this record far more than in the average normal record.
                        They describe how the record differs from normal traffic, not the model&apos;s internal reasoning.
                      </p>
                    </div>
                  )}
                </>
              )}
              {Object.entries(selectedThreat.data).map(([key, val]) => (
                <div key={key} className="kv-row">
                  <span className="kv-key">{key}</span>
                  <span className="kv-val">{val !== null ? String(val) : 'null'}</span>
                </div>
              ))}
            </div>

            <div className="modal-foot">
              <button type="button" className="scan-btn" onClick={() => setSelectedThreat(null)}>
                Close inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}