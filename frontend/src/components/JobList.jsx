import { LevelBadge, Spinner, seconds } from "./bits.jsx";

const STATUS_LABEL = {
  queued: "Queued",
  running: "Analyzing",
  done: "Done",
  failed: "Failed",
};

export default function JobList({ jobs, selectedId, onSelect, onRemove }) {
  if (!jobs.length) return null;
  const active = jobs.filter((job) => job.status === "queued" || job.status === "running");

  return (
    <div className="card" data-testid="job-list">
      <div className="card-head">
        <h2>Analyses</h2>
        {active.length > 0 && <span className="muted">{active.length} in progress</span>}
      </div>
      <ul className="jobs">
        {jobs.map((job) => (
          <li key={job.id}>
            {/* Two sibling buttons: opening a report and removing the row
                are separate controls, so neither is nested in the other. */}
            <div
              className={`job ${job.id === selectedId ? "job-selected" : ""}`}
              data-testid="job"
              data-status={job.status}
              data-package={job.package_name}
            >
              <button
                type="button"
                className="job-open"
                aria-current={job.id === selectedId ? "true" : undefined}
                onClick={() => onSelect(job.id)}
              >
                <span className="job-main">
                  <span className="job-title">
                    <span className="mono">{job.package_name}</span>
                    <span className="job-versions mono">
                      {job.current_version} → {job.target_version}
                    </span>
                  </span>
                  <span className="job-sub">{job.project_name}</span>
                </span>
                <span className="job-side">
                  {job.status === "done" ? (
                    <span className="job-levels">
                      <LevelBadge level={job.migration_risk} label="risk" />
                      <LevelBadge level={job.upgrade_urgency} label="urgency" />
                    </span>
                  ) : (
                    <span className={`job-status job-status-${job.status}`}>
                      {(job.status === "running" || job.status === "queued") && <Spinner />}
                      {STATUS_LABEL[job.status]}
                      {job.status === "running" && job.run_seconds != null && (
                        <span className="mono"> {seconds(job.run_seconds)}</span>
                      )}
                    </span>
                  )}
                </span>
              </button>
              <button
                type="button"
                className="job-remove"
                aria-label="Remove from list"
                title="Remove from list"
                onClick={() => onRemove(job.id)}
              >
                ×
              </button>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
}
