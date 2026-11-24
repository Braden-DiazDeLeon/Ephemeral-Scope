import { useCallback, useEffect, useRef, useState } from "react";
import { getAnalysis, getHealth, listAnalyses } from "./api.js";
import NewAnalysis from "./components/NewAnalysis.jsx";
import JobList from "./components/JobList.jsx";
import Report from "./components/Report.jsx";
import { Logo } from "./components/bits.jsx";

const STORAGE_KEY = "ephemeral-scope.jobs";
const POLL_MS = 700;
const MAX_REMEMBERED = 30;

function rememberedIds() {
  try {
    const ids = JSON.parse(localStorage.getItem(STORAGE_KEY) || "[]");
    return Array.isArray(ids) ? ids.filter((id) => typeof id === "string") : [];
  } catch {
    return [];
  }
}

function remember(ids) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(ids.slice(0, MAX_REMEMBERED)));
  } catch {
    // Private windows may refuse storage; the list simply will not persist.
  }
}

const isActive = (job) => job.status === "queued" || job.status === "running";

export default function App() {
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState(null);
  const [jobs, setJobs] = useState([]);
  const [details, setDetails] = useState({});
  const [selectedId, setSelectedId] = useState(null);
  const [detailError, setDetailError] = useState(null);
  const loading = useRef(new Set());

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch((error) => setHealthError(error.message));
  }, []);

  // Restore the jobs this browser started earlier, if the server still has them.
  useEffect(() => {
    const ids = rememberedIds();
    if (!ids.length) return;
    listAnalyses(ids)
      .then(({ analyses }) => {
        const byId = new Map(analyses.map((job) => [job.id, job]));
        const restored = ids.map((id) => byId.get(id)).filter(Boolean);
        setJobs((current) => {
          const known = new Set(current.map((job) => job.id));
          return [...current, ...restored.filter((job) => !known.has(job.id))];
        });
        setSelectedId((current) => current ?? restored[0]?.id ?? null);
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    remember(jobs.map((job) => job.id));
  }, [jobs]);

  // Poll only while something is queued or running.
  const anyActive = jobs.some(isActive);
  const activeKey = jobs.filter(isActive).map((job) => job.id).join(",");
  useEffect(() => {
    if (!anyActive) return undefined;
    let cancelled = false;
    let timer;
    const tick = async () => {
      try {
        const { analyses, missing } = await listAnalyses(activeKey.split(","));
        if (cancelled) return;
        const fresh = new Map(analyses.map((job) => [job.id, job]));
        const gone = new Set(missing);
        setJobs((current) =>
          current
            .map((job) => {
              if (fresh.has(job.id)) return fresh.get(job.id);
              if (gone.has(job.id)) {
                return { ...job, status: "failed", error: "The server no longer has this analysis." };
              }
              return job;
            }),
        );
      } catch {
        // A dropped poll is retried on the next tick.
      }
      if (!cancelled) timer = setTimeout(tick, POLL_MS);
    };
    timer = setTimeout(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [anyActive, activeKey]);

  // Fetch the full report once, when the selected job has finished.
  const selected = jobs.find((job) => job.id === selectedId) || null;
  const selectedStatus = selected?.status;
  useEffect(() => {
    if (!selectedId || selectedStatus !== "done") return;
    if (details[selectedId] || loading.current.has(selectedId)) return;
    loading.current.add(selectedId);
    setDetailError(null);
    getAnalysis(selectedId)
      .then((detail) => setDetails((current) => ({ ...current, [detail.id]: detail })))
      .catch((error) => setDetailError(error.message))
      .finally(() => loading.current.delete(selectedId));
  }, [selectedId, selectedStatus, details]);

  const handleSubmitted = useCallback((job) => {
    setJobs((current) => [job, ...current.filter((item) => item.id !== job.id)]);
    setSelectedId(job.id);
  }, []);

  const handleRemove = useCallback((id) => {
    setJobs((current) => current.filter((job) => job.id !== id));
    setSelectedId((current) => (current === id ? null : current));
  }, []);

  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Logo size={26} />
          <span className="brand-name">Ephemeral Scope</span>
          <span className="brand-tag">dependency upgrade risk</span>
        </div>
        <div className="status" data-testid="health">
          {healthError && <span className="chip chip-bad">server offline</span>}
          {health && (
            <>
              <span className={`chip ${health.prolog ? "" : "chip-warn"}`}>
                {health.prolog ? "Prolog engine" : "Python fallback"}
              </span>
              <span className={`chip ${health.classifier === "hybrid" ? "" : "chip-warn"}`}>
                {health.classifier === "hybrid" ? "hybrid classifier" : "rules only"}
              </span>
              <span className="chip">{health.max_concurrent} parallel</span>
            </>
          )}
        </div>
      </header>

      <main className="layout">
        <aside className="sidebar">
          <NewAnalysis onSubmitted={handleSubmitted} />
          <JobList
            jobs={jobs}
            selectedId={selectedId}
            onSelect={setSelectedId}
            onRemove={handleRemove}
          />
        </aside>
        <section className="content">
          <Report
            job={selected}
            detail={selected ? details[selected.id] : null}
            error={detailError}
          />
        </section>
      </main>
    </div>
  );
}
