import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";

const PAGE_SIZE = 1000;
const IP_PATTERN = /(?<![A-Za-z0-9])(?:\d{1,3}\.){3}\d{1,3}(?!\d)|(?<![A-Fa-f0-9])[A-Fa-f0-9:]{3,39}(?![A-Fa-f0-9])/g;
const TIMESTAMP_EXAMPLE = "2026-10-12T14:51:27.194387Z";
const TIMESTAMP_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/i;
const LEVELS = ["TRACE", "DEBUG", "INFO", "WARN", "ERROR"];
const AGE_OPTIONS = [
  { label: "1 min", value: 60 },
  { label: "5 min", value: 300 },
  { label: "30 min", value: 1800 },
  { label: "1 hour", value: 3600 },
  { label: "6 hours", value: 21600 },
];

async function requestJson(path) {
  const response = await fetch(path);
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function formatTime(timestamp) {
  if (!timestamp) return "—";
  return new Date(Number(timestamp) / 1000).toLocaleTimeString([], {
    hour12: false,
    fractionalSecondDigits: 3,
  });
}

function timestampToInputValue(timestampUs) {
  const value = Number(timestampUs);
  if (!Number.isSafeInteger(value) || value < 0) return "";
  const date = new Date(Math.floor(value / 1000));
  if (Number.isNaN(date.getTime())) return "";
  const seconds = date.toISOString().slice(0, -5);
  const fraction = String(value % 1_000_000).padStart(6, "0");
  return `${seconds}.${fraction}Z`;
}

function parseTimestampInput(value) {
  const match = TIMESTAMP_PATTERN.exec(value.trim());
  if (!match) return null;
  const [, year, month, day, hour, minute, second, fraction = "", zone] = match;
  const parts = [year, month, day, hour, minute, second].map(Number);
  const [yearNumber, monthNumber, dayNumber, hourNumber, minuteNumber, secondNumber] = parts;
  if (monthNumber < 1 || monthNumber > 12 || hourNumber > 23 || minuteNumber > 59 || secondNumber > 59) return null;

  const calendar = new Date(0);
  calendar.setUTCFullYear(yearNumber, monthNumber - 1, dayNumber);
  calendar.setUTCHours(hourNumber, minuteNumber, secondNumber, 0);
  if (
    calendar.getUTCFullYear() !== yearNumber
    || calendar.getUTCMonth() !== monthNumber - 1
    || calendar.getUTCDate() !== dayNumber
  ) return null;

  const normalizedZone = zone.toUpperCase();
  if (normalizedZone !== "Z") {
    const offset = /^([+-])(\d{2}):(\d{2})$/.exec(normalizedZone);
    const offsetHours = offset?.[2];
    const offsetMinutes = offset?.[3];
    if (offsetHours === undefined || Number(offsetHours) > 23 || Number(offsetMinutes) > 59) return null;
  }
  const baseMilliseconds = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}.000${normalizedZone}`);
  if (!Number.isFinite(baseMilliseconds)) return null;
  const fractionalMicroseconds = Number(fraction.padEnd(6, "0").slice(0, 6));
  const timestampUs = baseMilliseconds * 1000 + fractionalMicroseconds;
  return Number.isSafeInteger(timestampUs) && timestampUs >= 0 ? timestampUs : null;
}

function readUrlTimestamp(params, name, fallback) {
  const timestamp = params.get(name);
  if (timestamp !== null) {
    const parsed = parseTimestampInput(timestamp);
    if (parsed === null) throw new Error(`Invalid "${name}" timestamp. Use a timestamp like ${TIMESTAMP_EXAMPLE}.`);
    return parsed;
  }
  const microseconds = params.get(`${name}_us`);
  if (microseconds !== null) {
    if (!/^\d+$/.test(microseconds)) throw new Error(`Invalid "${name}_us" timestamp; expected Unix microseconds.`);
    const parsed = Number(microseconds);
    if (!Number.isSafeInteger(parsed)) throw new Error(`"${name}_us" is outside the supported timestamp range.`);
    return parsed;
  }
  const parsed = parseTimestampInput(fallback);
  if (parsed === null) throw new Error("The fallback timestamp range is invalid.");
  return parsed;
}

function rangeFromUrl(search, fallback) {
  const params = new URLSearchParams(search);
  return {
    from: timestampToInputValue(readUrlTimestamp(params, "from", fallback.from)),
    to: timestampToInputValue(readUrlTimestamp(params, "to", fallback.to)),
  };
}

function rangeFromHistory(status) {
  const nowUs = Date.now() * 1000;
  const fromUs = Number(status.log_oldest_available ?? status.started_at ?? nowUs - 60 * 60 * 1_000_000);
  return {
    from: timestampToInputValue(fromUs),
    to: timestampToInputValue(nowUs),
  };
}

function updateUrlRange(fromUs, toUs) {
  const url = new URL(window.location.href);
  url.searchParams.set("from", timestampToInputValue(fromUs));
  url.searchParams.set("to", timestampToInputValue(toUs));
  url.searchParams.delete("from_us");
  url.searchParams.delete("to_us");
  const nextUrl = `${url.pathname}${url.search}${url.hash}`;
  const currentUrl = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  if (nextUrl !== currentUrl) window.history.pushState({ fromUs, toUs }, "", nextUrl);
}

function levelClass(level = "INFO") {
  return `level-${level.toLowerCase()}`;
}

function displayLabel(value = "") {
  const lower = value.toLowerCase().replaceAll("_", " ");
  return lower.replace(/\b[a-z]/g, (letter) => letter.toUpperCase());
}

function ipTokens(text) {
  const tokens = [];
  let last = 0;
  for (const match of text.matchAll(IP_PATTERN)) {
    const value = match[0];
    const index = match.index ?? 0;
    if (!value.includes(".") && !value.includes(":")) continue;
    if (index > last) tokens.push(text.slice(last, index));
    tokens.push({ ip: value });
    last = index + value.length;
  }
  if (last < text.length) tokens.push(text.slice(last));
  return tokens.length ? tokens : [text];
}

function App() {
  const [page, setPage] = useState("logs");
  const [history, setHistory] = useState(null);
  const [streamState, setStreamState] = useState("connecting");
  const [activityVersion, setActivityVersion] = useState(0);
  const [selection, setSelection] = useState(null);
  const [selectedConnection, setSelectedConnection] = useState(null);
  const [notice, setNotice] = useState("");
  const [logs, setLogs] = useState([]);
  const initialNowUs = Date.now() * 1000;
  const [range, setRange] = useState({
    from: timestampToInputValue(initialNowUs - 60 * 60 * 1_000_000),
    to: timestampToInputValue(initialNowUs),
  });
  const [queryRange, setQueryRange] = useState(null);
  const [totalLogs, setTotalLogs] = useState(0);
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [textFilter, setTextFilter] = useState("");
  const [loadingLogs, setLoadingLogs] = useState(false);
  const [connections, setConnections] = useState([]);
  const [connectionAge, setConnectionAge] = useState(3600);
  const [loadingConnections, setLoadingConnections] = useState(false);
  const nextOffset = useRef(0);
  const loadingMore = useRef(false);
  const querySequence = useRef(0);
  const logKeysRef = useRef(new Set());
  const queryRangeRef = useRef(null);
  const pendingLiveLogs = useRef([]);
  const liveFlushTimer = useRef(null);

  const refreshHistory = useCallback(async () => {
    try {
      const status = await requestJson("/v1/history");
      setHistory(status);
      return status;
    } catch (error) {
      setNotice(error.message);
      return null;
    }
  }, []);

  const loadLogPage = useCallback(async (fromUs, toUs, offset, replace, queryId) => {
    if (loadingMore.current && !replace) return;
    loadingMore.current = true;
    setLoadingLogs(true);
    try {
      const params = new URLSearchParams({
        from_us: String(fromUs),
        to_us: String(toUs),
        offset: String(offset),
        limit: String(PAGE_SIZE),
      });
      const pageData = await requestJson(`/v1/logs?${params}`);
      if (queryId !== querySequence.current) return;
      if (replace) {
        const pending = pendingLiveLogs.current.splice(0);
        const ordered = mergeSorted(pageData.logs, pending);
        logKeysRef.current = new Set(ordered.map(logKey));
        setLogs(ordered);
      } else {
        const incoming = pageData.logs.filter((entry) => {
          const key = logKey(entry);
          if (logKeysRef.current.has(key)) return false;
          logKeysRef.current.add(key);
          return true;
        });
        setLogs((current) => mergeSorted(current, incoming));
      }
      setTotalLogs(pageData.total);
      nextOffset.current = offset + pageData.logs.length;
      setQueryRange({ fromUs, toUs });
      queryRangeRef.current = { fromUs, toUs };
      setNotice("");
    } catch (error) {
      if (queryId !== querySequence.current) return;
      setNotice(error.message);
      if (error.message.includes("persisted files")) refreshHistory();
    } finally {
      if (queryId === querySequence.current) {
        loadingMore.current = false;
        setLoadingLogs(false);
      }
    }
  }, [refreshHistory]);

  const runLogQuery = useCallback(async (
    nextRange = range,
    { status: knownStatus, updateUrl = true } = {},
  ) => {
    const queryId = ++querySequence.current;
    const fromUs = parseTimestampInput(nextRange.from);
    const toUs = parseTimestampInput(nextRange.to);
    if (fromUs === null || toUs === null) {
      loadingMore.current = false;
      setLoadingLogs(false);
      setNotice(`Enter timestamps like ${TIMESTAMP_EXAMPLE}.`);
      return;
    }
    if (fromUs > toUs) {
      loadingMore.current = false;
      setLoadingLogs(false);
      setNotice("The start timestamp must be earlier than or equal to the end timestamp.");
      return;
    }
    if (updateUrl) updateUrlRange(fromUs, toUs);
    const status = knownStatus || history || (await refreshHistory());
    if (!status) return;
    if (queryId !== querySequence.current) return;
    setLogs([]);
    logKeysRef.current.clear();
    queryRangeRef.current = { fromUs, toUs };
    pendingLiveLogs.current = [];
    clearTimeout(liveFlushTimer.current);
    liveFlushTimer.current = null;
    setTotalLogs(0);
    nextOffset.current = 0;
    await loadLogPage(fromUs, toUs, 0, true, queryId);
  }, [history, loadLogPage, range, refreshHistory]);

  useEffect(() => {
    let alive = true;
    refreshHistory().then((status) => {
      if (!alive || !status) return;
      const fallback = rangeFromHistory(status);
      try {
        const nextRange = rangeFromUrl(window.location.search, fallback);
        setRange(nextRange);
        runLogQuery(nextRange, { status, updateUrl: false });
      } catch (error) {
        setRange(fallback);
        setNotice(error.message);
      }
    });
    const handlePopState = () => {
      refreshHistory().then((status) => {
        if (!alive || !status) return;
        const fallback = rangeFromHistory(status);
        try {
          const nextRange = rangeFromUrl(window.location.search, fallback);
          setRange(nextRange);
          runLogQuery(nextRange, { status, updateUrl: false });
        } catch (error) {
          setRange(fallback);
          setNotice(error.message);
        }
      });
    };
    window.addEventListener("popstate", handlePopState);
    const events = new EventSource("/v1/stream");
    events.onopen = () => setStreamState("live");
    events.onerror = () => setStreamState("reconnecting");
    events.onmessage = (message) => {
      try {
        const event = JSON.parse(message.data);
        if (event.type === "gap") {
          setNotice("Live stream fell behind; reload the selected time range to fill the gap.");
          setActivityVersion((version) => version + 1);
        } else if (event.type === "log") {
          const entry = event.data;
          const activeRange = queryRangeRef.current;
          const key = logKey(entry);
          if (!activeRange || Number(entry.ts) < activeRange.fromUs || logKeysRef.current.has(key)) return;
          logKeysRef.current.add(key);
          pendingLiveLogs.current.push(entry);
          if (!liveFlushTimer.current) {
            liveFlushTimer.current = setTimeout(() => {
              const batch = pendingLiveLogs.current.splice(0);
              liveFlushTimer.current = null;
              setLogs((current) => mergeSorted(current, batch));
              setTotalLogs((count) => count + batch.length);
            }, 150);
          }
        } else if (event.type === "activity") {
          setActivityVersion((version) => version + 1);
        }
      } catch {
        setNotice("Received an unreadable live event.");
      }
    };
    return () => {
      alive = false;
      window.removeEventListener("popstate", handlePopState);
      events.close();
      clearTimeout(liveFlushTimer.current);
    };
  }, []);

  useEffect(() => {
    if (page !== "connections") return;
    let alive = true;
    setLoadingConnections(true);
    requestJson(`/v1/connections?age_seconds=${connectionAge}`)
      .then((data) => {
        if (alive) {
          setConnections(data.connections);
          setNotice(data.history_partial ? `Showing retained connection history since ${formatTime(data.available_from)}.` : "");
        }
      })
      .catch((error) => {
        if (alive) setNotice(error.message);
      })
      .finally(() => {
        if (alive) setLoadingConnections(false);
      });
    return () => {
      alive = false;
    };
  }, [page, connectionAge, activityVersion]);

  const visibleLogs = useMemo(() => {
    const needle = textFilter.trim().toLowerCase();
    return logs.filter((entry) => {
      const levelMatches = levelFilter === "ALL" || entry.level === levelFilter;
      const text = `${entry.target} ${entry.message} ${(entry.fields || []).map((field) => `${field.name}=${field.value}`).join(" ")}`.toLowerCase();
      return levelMatches && (!needle || text.includes(needle));
    });
  }, [logs, levelFilter, textFilter]);

  const loadMore = useCallback(() => {
    if (!queryRange || loadingMore.current || nextOffset.current >= totalLogs) return;
    loadLogPage(queryRange.fromUs, queryRange.toUs, nextOffset.current, false, querySequence.current);
  }, [loadLogPage, queryRange, totalLogs]);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">n</div>
          <div><strong>nsproxy</strong><span>serve console</span></div>
        </div>
        <div className="profile-label">Live profile</div>
        <div className="profile-card">
          <span className={`live-dot ${streamState === "live" ? "" : "dim"}`} />
          <div><strong>serve instance</strong><small>{streamState === "live" ? "stream connected" : streamState}</small></div>
          <span className="profile-menu">•••</span>
        </div>
        <nav className="nav-list">
          <button className={page === "logs" ? "nav-item active" : "nav-item"} onClick={() => setPage("logs")}>
            <span className="nav-icon">≋</span><span>Log stream</span><kbd>01</kbd>
          </button>
          <button className={page === "connections" ? "nav-item active" : "nav-item"} onClick={() => setPage("connections")}>
            <span className="nav-icon">◉</span><span>Connections</span><kbd>02</kbd>
          </button>
        </nav>
        <div className="sidebar-bottom">
          <div className="budget-label"><span>History buffer</span><b>{history ? `${Math.round(history.used_bytes / 1024 / 1024)} / ${Math.round(history.max_bytes / 1024 / 1024)} MB` : "—"}</b></div>
          <div className="budget-track"><i style={{ width: `${history ? Math.min(100, history.used_bytes / history.max_bytes * 100) : 0}%` }} /></div>
          <div className="sidebar-foot"><span className="status-dot" /> In-memory · bounded</div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumbs"><span>Workspace</span><b>/</b><strong>{page === "logs" ? "Log stream" : "Connections"}</strong></div>
          <div className="topbar-right"><span className="secure-label">Profile network</span><span className="stream-pill"><i /> {streamState === "live" ? "Live" : "Reconnecting"}</span></div>
        </header>
        <section className="page-content">
          {notice && <div className="notice"><span>!</span>{notice}<button onClick={() => setNotice("")}>×</button></div>}
          {page === "logs" ? (
            <LogPage
              logs={visibleLogs}
              total={totalLogs}
              loading={loadingLogs}
              range={range}
              setRange={setRange}
              runQuery={() => runLogQuery(range)}
              levelFilter={levelFilter}
              setLevelFilter={setLevelFilter}
              textFilter={textFilter}
              setTextFilter={setTextFilter}
              loadMore={loadMore}
              onSelectIp={(ip, at) => { setSelection({ ip, at }); setSelectedConnection(null); }}
              setPage={setPage}
            />
          ) : (
            <ConnectionsPage
              connections={connections}
              age={connectionAge}
              setAge={setConnectionAge}
              loading={loadingConnections}
              onSelect={(connection) => setSelectedConnection(connection)}
              activityVersion={activityVersion}
              historyStartedAt={history?.activity_oldest_available}
            />
          )}
        </section>
      </main>

      {(selection || selectedConnection) && (
        <ContextPanel
          selection={selection}
          connection={selectedConnection}
          age={connectionAge}
          onClose={() => { setSelection(null); setSelectedConnection(null); }}
          onSelectConnection={setSelectedConnection}
        />
      )}
    </div>
  );
}

function logKey(entry) {
  return `${entry.ts}|${entry.level}|${entry.target}|${entry.message}`;
}

function mergeSorted(left, right) {
  const merged = [];
  const seen = new Set();
  let i = 0;
  let j = 0;
  while (i < left.length || j < right.length) {
    let next;
    if (i >= left.length) next = right[j++];
    else if (j >= right.length) next = left[i++];
    else if (Number(left[i].ts) <= Number(right[j].ts)) next = left[i++];
    else next = right[j++];
    const key = logKey(next);
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(next);
    }
  }
  return merged;
}

function LogPage(props) {
  const scrollRef = useRef(null);
  const rowVirtualizer = useVirtualizer({
    count: props.logs.length + (props.logs.length < props.total ? 1 : 0),
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 62,
    overscan: 14,
  });
  const items = rowVirtualizer.getVirtualItems();
  useEffect(() => {
    if (items.some((item) => item.index >= props.logs.length - 12)) props.loadMore();
  }, [items, props.logs.length, props.loadMore]);

  return (
    <>
      <div className="title-row">
        <div><div className="eyebrow"><span className="pulse" /> Log history</div><h1>Log stream</h1><p className="subtitle">A live trace of what this serve instance is doing.</p></div>
        <div className="title-actions"><span className="counter-chip"><b>{props.total.toLocaleString()}</b> retained events</span><button className="icon-button" title="Refresh history" onClick={props.runQuery}>↻</button></div>
      </div>
      <div className="filter-bar">
        <label className="date-control"><span>From</span><input type="text" inputMode="text" autoComplete="off" spellCheck={false} aria-label="From timestamp in RFC 3339 format" placeholder={TIMESTAMP_EXAMPLE} value={props.range.from} onChange={(event) => props.setRange({ ...props.range, from: event.target.value })} onKeyDown={(event) => event.key === "Enter" && props.runQuery()} /></label>
        <span className="range-arrow">→</span>
        <label className="date-control"><span>To</span><input type="text" inputMode="text" autoComplete="off" spellCheck={false} aria-label="To timestamp in RFC 3339 format" placeholder={TIMESTAMP_EXAMPLE} value={props.range.to} onChange={(event) => props.setRange({ ...props.range, to: event.target.value })} onKeyDown={(event) => event.key === "Enter" && props.runQuery()} /></label>
        <div className="filter-divider" />
        <label className="search-control"><span>⌕</span><input placeholder="Filter messages or targets…" value={props.textFilter} onChange={(event) => props.setTextFilter(event.target.value)} /></label>
        <select className="select-control" value={props.levelFilter} onChange={(event) => props.setLevelFilter(event.target.value)}>
          <option value="ALL">All levels</option>
          {LEVELS.map((level) => <option key={level} value={level}>{displayLabel(level)}</option>)}
        </select>
        <button className="primary-button" onClick={props.runQuery}>Query range <span>↗</span></button>
      </div>
      <div className="log-panel">
        <div className="panel-heading">
          <div className="panel-title"><span className="panel-glyph">▤</span><strong>Events</strong><span className="muted">· {props.logs.length.toLocaleString()} loaded</span></div>
          <div className="panel-columns"><span>Timestamp</span><span>Level</span><span>Message</span></div>
        </div>
        <div className="log-scroll" ref={scrollRef}>
          {props.logs.length === 0 && !props.loading ? <div className="empty-state"><div>◌</div><strong>No events in this range</strong><span>Choose another timestamp range and run a query.</span></div> : (
            <div className="virtual-space" style={{ height: `${rowVirtualizer.getTotalSize()}px` }}>
              {items.map((virtualRow) => {
                const entry = props.logs[virtualRow.index];
                if (!entry) return <div key="loading" className="load-row" style={{ transform: `translateY(${virtualRow.start}px)` }}>{props.loading ? "Loading more history…" : "Scroll to load more"}</div>;
                return (
                  <LogRow
                    key={`${logKey(entry)}-${virtualRow.index}`}
                    entry={entry}
                    index={virtualRow.index}
                    measure={rowVirtualizer.measureElement}
                    start={virtualRow.start}
                    onSelectIp={props.onSelectIp}
                    setPage={props.setPage}
                  />
                );
              })}
            </div>
          )}
        </div>
        <div className="log-footer"><span><i className="live-dot" /> Streaming new events</span><span>{props.logs.length.toLocaleString()} / {props.total.toLocaleString()} loaded <b>·</b> virtualized</span></div>
      </div>
    </>
  );
}

function LogRow({ entry, index, measure, start, onSelectIp, setPage }) {
  const text = `${entry.message || ""} ${(entry.fields || []).map((field) => `${field.name}=${field.value}`).join(" ")}`.trim();
  const target = entry.target || "nsproxy";
  const timestamp = Number(entry.ts);
  return (
    <div ref={measure} data-index={index} className="log-row" style={{ transform: `translateY(${start}px)` }}>
      <span className="log-time">{formatTime(entry.ts)}</span>
      <span className={`level-badge ${levelClass(entry.level)}`}>{displayLabel(entry.level || "INFO")}</span>
      <div className="log-message">
        <span className="log-target">{target}</span>
        <span className="message-text">
          {ipTokens(text).map((part, tokenIndex) => typeof part === "string"
            ? <span key={tokenIndex}>{part}</span>
            : <IpToken key={`${part.ip}-${tokenIndex}`} ip={part.ip} at={timestamp} onSelect={() => onSelectIp(part.ip, timestamp)} />)}
        </span>
      </div>
    </div>
  );
}

function IpToken({ ip, at, onSelect }) {
  const [mapping, setMapping] = useState(null);
  const [hovered, setHovered] = useState(false);
  const timer = useRef(null);
  useEffect(() => {
    if (!hovered) return undefined;
    timer.current = setTimeout(() => {
      requestJson(`/v1/virtual-ips/${encodeURIComponent(ip)}?at_us=${at}`)
        .then((data) => setMapping(data.mapping))
        .catch(() => setMapping(null));
    }, 100);
    return () => clearTimeout(timer.current);
  }, [hovered, ip, at]);
  return (
    <span className="ip-token-wrap" onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      <button className="ip-token" onClick={onSelect}>{ip}</button>
      {hovered && <span className="ip-tooltip">
        <b>{mapping?.domain || "IP context"}</b>
        <small>{mapping ? `Virtual mapping · since ${formatTime(mapping.valid_from)}` : "Click to inspect address context"}</small>
        <i>Click to dive in <span>↗</span></i>
      </span>}
    </span>
  );
}

function ConnectionsPage({ connections, age, setAge, loading, onSelect, historyStartedAt }) {
  const active = connections.filter((connection) => connection.finished_at == null);
  const finished = connections.filter((connection) => connection.finished_at != null);
  return (
    <>
      <div className="title-row">
        <div><div className="eyebrow"><span className="pulse" /> Connection activity</div><h1>Connections</h1><p className="subtitle">Active flows and recently completed TCP / UDP activity.</p></div>
        <div className="title-actions"><span className="counter-chip"><b>{active.length}</b> active</span><span className="counter-chip"><b>{finished.length}</b> recently closed</span></div>
      </div>
      <div className="connection-toolbar">
        <div className="filter-caption"><span>◷</span> History window</div>
        <div className="age-control">{AGE_OPTIONS.map((option) => (
          <button key={option.value} className={age === option.value ? "age-option selected" : "age-option"} onClick={() => setAge(option.value)}>{option.label}</button>
        ))}</div>
        <div className="toolbar-note">Active flows included <span>·</span> history since {formatTime(historyStartedAt)}</div>
      </div>
      <div className="connection-grid">
        <ConnectionSection title="Active now" count={active.length} empty="No active flows right now." connections={active} loading={loading} onSelect={onSelect} />
        <ConnectionSection title="Recently closed" count={finished.length} empty={`No completed activity in the selected ${AGE_OPTIONS.find((option) => option.value === age)?.label || "window"}.`} connections={finished} loading={loading} onSelect={onSelect} />
      </div>
    </>
  );
}

function ConnectionSection({ title, count, empty, connections, loading, onSelect }) {
  return (
    <section className="connection-section">
      <div className="section-heading"><div><span className={title === "Active now" ? "section-live" : "section-closed"} />{title}</div><span>{count}</span></div>
      {loading && <div className="small-loading">Updating activity…</div>}
      {!loading && connections.length === 0 && <div className="connection-empty">{empty}</div>}
      <div className="connection-list">
        {connections.map((connection) => (
          <button className="connection-card" key={connection.id} onClick={() => onSelect(connection)}>
            <div className="connection-card-top">
              <span className={`protocol-badge ${connection.kind === "Udp" ? "udp" : "tcp"}`}>{connection.kind || "Flow"}</span>
              <span className="connection-age">{formatTime(connection.finished_at || connection.accepted_at)}</span>
              <span className={connection.finished_at == null ? "connection-state active" : "connection-state"}>{connection.finished_at == null ? "Active" : "Closed"}</span>
            </div>
            <div className="connection-destination">{connection.dst || "Unknown destination"}</div>
            <div className="connection-card-bottom">
              <span>{connection.src || "source unavailable"}</span>
              <span>{connection.connected_at ? "Connected" : "Pending"} <b>·</b> #{connection.id}</span>
            </div>
          </button>
        ))}
      </div>
    </section>
  );
}

function ContextPanel({ selection, connection, age, onClose, onSelectConnection }) {
  const [mapping, setMapping] = useState(null);
  const [related, setRelated] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  useEffect(() => {
    if (!selection) return undefined;
    let alive = true;
    setLoading(true);
    setError("");
    Promise.all([
      requestJson(`/v1/virtual-ips/${encodeURIComponent(selection.ip)}?at_us=${selection.at}`),
      requestJson(`/v1/connections?age_seconds=${age}&ip=${encodeURIComponent(selection.ip)}`),
    ]).then(([mappingData, connectionsData]) => {
      if (alive) {
        setMapping(mappingData.mapping);
        setRelated(connectionsData.connections);
      }
    }).catch((reason) => {
      if (alive) {
        setMapping(null);
        setError(reason.message);
        requestJson(`/v1/connections?age_seconds=${age}&ip=${encodeURIComponent(selection.ip)}`)
          .then((data) => alive && setRelated(data.connections))
          .catch(() => {});
      }
    }).finally(() => alive && setLoading(false));
    return () => { alive = false; };
  }, [selection, age]);

  const selected = connection;
  return (
    <div className="context-backdrop" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <aside className="context-panel">
        <div className="context-header"><div><div className="eyebrow">Details</div><h2>{selected ? `Flow #${selected.id}` : selection.ip}</h2></div><button className="icon-button" onClick={onClose}>×</button></div>
        {selected ? (
          <ConnectionDetails connection={selected} />
        ) : (
          <>
            <div className="context-address"><span>Address at {formatTime(selection.at)}</span><strong>{selection.ip}</strong></div>
            {loading && <div className="small-loading">Resolving retained context…</div>}
            {mapping && <div className="mapping-card"><span>Virtual IP → domain</span><strong>{mapping.domain}</strong><small>Valid from {formatTime(mapping.valid_from)}{mapping.valid_until ? ` until ${formatTime(mapping.valid_until)}` : " · still active"}</small></div>}
            {error && <div className="context-error">{error}</div>}
            <div className="drawer-section-title">Flows mentioning this IP <span>{related.length}</span></div>
            <p className="drawer-section-description">Retained TCP/UDP records with this address in an endpoint or event.</p>
            {related.length === 0 && !loading ? <div className="connection-empty">No retained flows mention this IP in the selected history window.</div> : related.map((item) => (
              <button className="related-flow" key={item.id} onClick={() => onSelectConnection(item)}>
                <span className={`protocol-badge ${item.kind === "Udp" ? "udp" : "tcp"}`}>{item.kind || "Flow"}</span>
                <span><b>{item.src || "Unknown source"} → {item.dst || "Unknown destination"}</b><small>#{item.id} · {formatTime(item.accepted_at || item.connected_at || item.finished_at)}</small></span>
                <span className={item.finished_at == null ? "section-live" : "section-closed"} />
              </button>
            ))}
          </>
        )}
      </aside>
    </div>
  );
}

function ConnectionDetails({ connection }) {
  return (
    <>
      <div className="detail-status"><span className={`protocol-badge ${connection.kind === "Udp" ? "udp" : "tcp"}`}>{connection.kind || "Flow"}</span><span className={connection.finished_at == null ? "connection-state active" : "connection-state"}>{connection.finished_at == null ? "Active" : "Closed"}</span></div>
      <div className="detail-grid">
        <Detail label="Source" value={connection.src} />
        <Detail label="Destination" value={connection.dst} />
        <Detail label="Accepted" value={formatTime(connection.accepted_at)} />
        <Detail label="Connected" value={formatTime(connection.connected_at)} />
        <Detail label="Finished" value={formatTime(connection.finished_at)} />
        <Detail label="Transfer" value={connection.bytes_up == null ? "—" : `${formatBytes(connection.bytes_up)} up · ${formatBytes(connection.bytes_down)} down`} />
      </div>
      {connection.error && <div className="context-error">{connection.error}</div>}
      <div className="drawer-section-title">Event timeline <span>{connection.events?.length || 0}</span></div>
      <div className="timeline">
        {(connection.events || []).map((event, index) => (
          <div className="timeline-event" key={`${eventName(event)}-${index}`}>
            <i />
            <div><span>{eventName(event)}</span><small>{formatTime(event.ts)} {event.message || event.query || event.error || ""}</small></div>
          </div>
        ))}
      </div>
    </>
  );
}

function Detail({ label, value }) {
  return <div className="detail-item"><span>{label}</span><b>{value || "—"}</b></div>;
}

function eventName(event) {
  return displayLabel(Object.keys(event).find((key) => key !== "id") || "Event");
}

function formatBytes(value = 0) {
  const bytes = Math.max(0, Number(value));
  if (bytes < 1024) return `${bytes.toFixed(0)} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export default App;
