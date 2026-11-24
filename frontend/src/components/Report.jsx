import { useMemo, useState } from "react";
import { LevelBadge, Logo, Spinner, humanize, seconds } from "./bits.jsx";

const CATEGORY_ORDER = [
  "breaking_change",
  "deprecation",
  "security_fix",
  "behavioral_change",
  "bug_fix",
  "feature",
  "irrelevant",
];
const NOTE_PAGE = 25;

const REASON_TEXT = {
  section_rule: "section heading",
  keyword_rule: "keyword rule",
  rule_model_agreement: "rule and model agree",
  rule_preferred_over_model: "rule preferred over model",
  model_suggestion_only: "model suggestion only",
  no_evidence: "no evidence",
};

export default function Report({ job, detail, error }) {
  if (!job) return <Empty />;

  if (job.status === "queued" || job.status === "running") {
    return (
      <div className="state" data-testid="report-pending">
        <Spinner />
        <h2>
          {job.status === "queued" ? "Waiting for a free worker" : "Analyzing"}{" "}
          <span className="mono">{job.package_name}</span>
        </h2>
        <p className="muted mono">
          {job.current_version} → {job.target_version}
          {job.run_seconds != null ? ` · ${seconds(job.run_seconds)}` : ""}
        </p>
        <p className="muted">
          Reading your code, comparing both releases, and collecting release notes and
          advisories. You can queue another analysis while this runs.
        </p>
      </div>
    );
  }

  if (job.status === "failed") {
    return (
      <div className="state" data-testid="report-failed">
        <h2>Analysis failed</h2>
        <p className="error">{job.error || "Something went wrong."}</p>
      </div>
    );
  }

  if (error && !detail) {
    return (
      <div className="state">
        <h2>Could not load the report</h2>
        <p className="error">{error}</p>
      </div>
    );
  }

  if (!detail?.report) {
    return (
      <div className="state">
        <Spinner />
        <p className="muted">Loading report…</p>
      </div>
    );
  }

  return <ReportBody job={detail} report={detail.report} />;
}

function Empty() {
  return (
    <div className="state empty" data-testid="empty">
      <Logo size={64} />
      <h1>Will this upgrade break your project?</h1>
      <p className="muted">
        Upload a Python project and pick a dependency upgrade. Ephemeral Scope finds the
        code the new version actually touches, reads the release notes and security
        advisories, and explains the risk.
      </p>
    </div>
  );
}

function ReportBody({ job, report }) {
  const { upgrade } = report;
  const vulnerabilities = report.vulnerabilities;
  const vulnerabilityCount =
    vulnerabilities.fixed.length +
    vulnerabilities.remaining.length +
    vulnerabilities.introduced.length;

  return (
    <article className="report" data-testid="report" data-job={job.id}>
      <header className="report-head">
        <div>
          <h1 className="mono" data-testid="report-title">
            {upgrade.package_name}{" "}
            <span className="report-versions">
              {upgrade.current_version} → {upgrade.target_version}
            </span>
          </h1>
          <p className="muted">
            {job.project_name}
            {job.run_seconds != null ? ` · analyzed in ${seconds(job.run_seconds)}` : ""}
            {report.declared_dependency?.specifier
              ? ` · declared ${report.declared_dependency.specifier}`
              : ""}
          </p>
        </div>
        <span className="chip" data-testid="engine">
          {report.inference_engine === "prolog" ? "Prolog inference" : "Python fallback"}
        </span>
      </header>

      <div className="verdicts">
        <Verdict
          title="Migration risk"
          question="Will this break my project?"
          level={report.migration_risk}
          reasons={report.migration_reasons}
          empty="No change lands on code this project uses."
          testId="migration-risk"
        />
        <Verdict
          title="Upgrade urgency"
          question="How badly do I need it?"
          level={report.upgrade_urgency}
          reasons={report.urgency_reasons}
          empty="No known advisory makes this upgrade urgent."
          testId="upgrade-urgency"
        />
      </div>

      {report.warnings.length > 0 && (
        <section className="warnings" data-testid="warnings">
          <h3>Incomplete evidence</h3>
          <ul>
            {report.warnings.map((warning, index) => (
              <li key={index}>
                <span className="tag">{warning.component}</span> {warning.message}
              </li>
            ))}
          </ul>
        </section>
      )}

      <Section title="What to do" count={report.migration_actions.length}>
        {report.migration_actions.length === 0 ? (
          <p className="muted">No action needed beyond the upgrade itself.</p>
        ) : (
          <ol className="actions" data-testid="actions">
            {report.migration_actions.map((action) => (
              <li key={action}>{action}</li>
            ))}
          </ol>
        )}
        {report.recommended_tests.length > 0 && (
          <div className="tests" data-testid="tests">
            <span className="label">Run these tests</span>
            {report.recommended_tests.map((test) => (
              <code key={test} className="pill mono">
                {test}
              </code>
            ))}
          </div>
        )}
      </Section>

      <Section title="Affected code" count={report.affected_usages.length}>
        {report.affected_usages.length === 0 ? (
          <p className="muted">
            {report.usage_count} usage{report.usage_count === 1 ? "" : "s"} of{" "}
            {upgrade.package_name} found; none is touched by an API change.
          </p>
        ) : (
          <div className="affected-list" data-testid="affected">
            {report.affected_usages.map((item, index) => (
              <Affected key={`${item.file}:${item.line}:${index}`} item={item} />
            ))}
          </div>
        )}
      </Section>

      <Section title="Security advisories" count={vulnerabilityCount}>
        {vulnerabilityCount === 0 ? (
          <p className="muted">No advisory affects either version.</p>
        ) : (
          <div data-testid="vulnerabilities">
            <VulnerabilityGroup
              title="Fixed by this upgrade"
              tone="good"
              records={vulnerabilities.fixed}
              testId="vuln-fixed"
            />
            <VulnerabilityGroup
              title="Still open in the target"
              tone="bad"
              records={vulnerabilities.remaining}
              testId="vuln-remaining"
            />
            <VulnerabilityGroup
              title="Introduced by the target"
              tone="bad"
              records={vulnerabilities.introduced}
              testId="vuln-introduced"
            />
          </div>
        )}
      </Section>

      <Section title="Why: rule findings" count={report.findings.length}>
        {report.findings.length === 0 ? (
          <p className="muted">No inference rule fired.</p>
        ) : (
          <ul className="findings" data-testid="findings">
            {report.findings.map((finding, index) => (
              <Finding key={index} finding={finding} />
            ))}
          </ul>
        )}
      </Section>

      <ReleaseNotes
        notes={report.release_notes}
        disagreements={report.classifier_disagreement_count}
      />

      <Section
        title="Project usage"
        count={report.usage_count}
        defaultOpen={false}
        aside={`${report.api_change_count.toLocaleString()} API changes between releases`}
      >
        <table className="table" data-testid="usages">
          <thead>
            <tr>
              <th>Symbol</th>
              <th>Kind</th>
              <th>Location</th>
            </tr>
          </thead>
          <tbody>
            {report.usages.map((usage, index) => (
              <tr key={index} className={usage.affected ? "row-affected" : ""}>
                <td className="mono">{usage.symbol}</td>
                <td>{humanize(usage.usage_kind)}</td>
                <td className="mono">
                  {usage.file}:{usage.line}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Section>
    </article>
  );
}

function Verdict({ title, question, level, reasons, empty, testId }) {
  return (
    <div className={`verdict verdict-${level}`} data-testid={testId} data-level={level}>
      <div className="verdict-head">
        <div>
          <div className="verdict-title">{title}</div>
          <div className="muted">{question}</div>
        </div>
        <span className={`verdict-level level-text-${level}`}>{level}</span>
      </div>
      {reasons.length === 0 ? (
        <p className="muted verdict-empty">{empty}</p>
      ) : (
        <ul className="reasons">
          {reasons.map((reason, index) => (
            <li key={index}>
              <span className={`dot dot-${reason.level}`} />
              <span>{humanize(reason.rule)}</span>
              <span className="mono reason-subject">{reason.subject}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function Section({ title, count, aside, defaultOpen = true, children }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <section className="section">
      <button
        type="button"
        className="section-head"
        aria-expanded={open}
        onClick={() => setOpen((value) => !value)}
      >
        <span className="section-title">
          {title}
          {count != null && <span className="count">{count}</span>}
        </span>
        <span className="section-aside">
          {aside && <span className="muted">{aside}</span>}
          <span className="caret">{open ? "−" : "+"}</span>
        </span>
      </button>
      {open && <div className="section-body">{children}</div>}
    </section>
  );
}

function Affected({ item }) {
  const { change, snippet } = item;
  return (
    <div className="affected" data-testid="affected-usage">
      <div className="affected-head">
        <span className="mono affected-loc">
          {item.file}:{item.line}
        </span>
        <span className="tag tag-high">{humanize(change.change_type)}</span>
      </div>
      <div className="mono affected-symbol">{item.symbol}</div>
      {snippet && (
        <pre className="code" data-testid="snippet">
          {snippet.lines.map((text, index) => {
            const number = snippet.start_line + index;
            const hit = number === snippet.highlight_line;
            return (
              <div key={number} className={`code-line ${hit ? "code-hit" : ""}`}>
                <span className="code-no">{number}</span>
                <span className="code-text">{text || " "}</span>
              </div>
            );
          })}
        </pre>
      )}
      {(change.old_signature || change.new_signature || change.details) && (
        <dl className="signature">
          {change.old_signature && (
            <>
              <dt>Before</dt>
              <dd className="mono">{change.old_signature}</dd>
            </>
          )}
          {change.new_signature && (
            <>
              <dt>After</dt>
              <dd className="mono">{change.new_signature}</dd>
            </>
          )}
          {change.details && (
            <>
              <dt>Detail</dt>
              <dd>{change.details}</dd>
            </>
          )}
        </dl>
      )}
    </div>
  );
}

function VulnerabilityGroup({ title, tone, records, testId }) {
  if (!records.length) return null;
  return (
    <div className="vuln-group" data-testid={testId}>
      <div className={`vuln-title vuln-${tone}`}>
        {title} <span className="count">{records.length}</span>
      </div>
      <ul className="vulns">
        {records.map((record) => (
          <li key={record.id}>
            {record.source_url ? (
              <a className="mono" href={record.source_url} target="_blank" rel="noreferrer">
                {record.id}
              </a>
            ) : (
              <span className="mono">{record.id}</span>
            )}
            <span className="vuln-summary">{record.summary}</span>
            {record.fixed_versions.length > 0 && (
              <span className="muted mono">fixed in {record.fixed_versions.join(", ")}</span>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Finding({ finding }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="finding">
      <div className="finding-head">
        <LevelBadge level={finding.risk_level} />
        <span className="mono finding-rule">{finding.rule_name}</span>
        {finding.file && (
          <span className="mono muted">
            {finding.file}
            {finding.line ? `:${finding.line}` : ""}
          </span>
        )}
      </div>
      <p>{finding.reason}</p>
      {finding.recommendation && <p className="muted">{finding.recommendation}</p>}
      {finding.supporting_facts.length > 0 && (
        <>
          <button type="button" className="link" onClick={() => setOpen((value) => !value)}>
            {open ? "Hide" : "Show"} supporting facts ({finding.supporting_facts.length})
          </button>
          {open && (
            <ul className="facts mono">
              {finding.supporting_facts.map((fact, index) => (
                <li key={index}>{fact}</li>
              ))}
            </ul>
          )}
        </>
      )}
    </li>
  );
}

function ReleaseNotes({ notes, disagreements }) {
  const [category, setCategory] = useState("all");
  const [relevantOnly, setRelevantOnly] = useState(false);
  const [limit, setLimit] = useState(NOTE_PAGE);

  const counts = useMemo(() => {
    const result = {};
    for (const note of notes) {
      const key = note.category || "unclassified";
      result[key] = (result[key] || 0) + 1;
    }
    return result;
  }, [notes]);
  const categories = [...CATEGORY_ORDER, "unclassified"].filter((key) => counts[key]);
  const relevantCount = notes.filter((note) => note.matched_project_symbols.length > 0).length;

  const filtered = useMemo(() => {
    const rank = (note) => {
      const index = CATEGORY_ORDER.indexOf(note.category);
      return index === -1 ? CATEGORY_ORDER.length : index;
    };
    return notes
      .filter((note) => category === "all" || (note.category || "unclassified") === category)
      .filter((note) => !relevantOnly || note.matched_project_symbols.length > 0)
      .map((note, index) => ({ note, index }))
      .sort(
        (a, b) =>
          b.note.matched_project_symbols.length - a.note.matched_project_symbols.length ||
          rank(a.note) - rank(b.note) ||
          a.index - b.index,
      )
      .map((entry) => entry.note);
  }, [notes, category, relevantOnly]);

  return (
    <Section
      title="Release notes"
      count={notes.length}
      aside={disagreements ? `${disagreements} rule/model disagreements` : null}
    >
      {notes.length === 0 ? (
        <p className="muted">No release notes were found between these versions.</p>
      ) : (
        <div data-testid="release-notes">
          <div className="filters">
            <button
              type="button"
              className={`filter ${category === "all" ? "filter-on" : ""}`}
              onClick={() => {
                setCategory("all");
                setLimit(NOTE_PAGE);
              }}
            >
              all {notes.length}
            </button>
            {categories.map((key) => (
              <button
                type="button"
                key={key}
                className={`filter ${category === key ? "filter-on" : ""}`}
                data-testid={`filter-${key}`}
                onClick={() => {
                  setCategory(key);
                  setLimit(NOTE_PAGE);
                }}
              >
                {humanize(key)} {counts[key]}
              </button>
            ))}
            {relevantCount > 0 && (
              <label className="check">
                <input
                  type="checkbox"
                  checked={relevantOnly}
                  onChange={(event) => setRelevantOnly(event.target.checked)}
                />
                Mentions my code ({relevantCount})
              </label>
            )}
          </div>
          <ul className="notes">
            {filtered.slice(0, limit).map((note, index) => (
              <Note key={index} note={note} />
            ))}
          </ul>
          {filtered.length === 0 && <p className="muted">Nothing matches this filter.</p>}
          {filtered.length > limit && (
            <button
              type="button"
              className="link"
              data-testid="more-notes"
              onClick={() => setLimit((value) => value + NOTE_PAGE)}
            >
              Show {Math.min(NOTE_PAGE, filtered.length - limit)} more of{" "}
              {filtered.length - limit}
            </button>
          )}
        </div>
      )}
    </Section>
  );
}

function Note({ note }) {
  const decision = note.decision;
  const key = note.category || "unclassified";
  return (
    <li className="note-item" data-testid="note" data-category={key}>
      <div className="note-meta">
        <span className={`tag tag-${key}`}>{humanize(key)}</span>
        <span className="mono muted">{note.release_version}</span>
        {note.section && <span className="muted">{note.section}</span>}
        {note.matched_project_symbols.length > 0 && (
          <span className="tag tag-relevant">
            uses {note.matched_project_symbols.slice(0, 2).join(", ")}
          </span>
        )}
        {note.source_url && (
          <a href={note.source_url} target="_blank" rel="noreferrer" className="muted">
            source
          </a>
        )}
      </div>
      <p className="note-text">{note.text}</p>
      {decision && (
        <p className="note-why muted">
          {REASON_TEXT[decision.selection_reason] || humanize(decision.selection_reason)}
          {" · rule: "}
          {decision.rule_category ? humanize(decision.rule_category) : "none"}
          {" · model: "}
          {decision.model_category
            ? `${humanize(decision.model_category)} (${Math.round(
                decision.model_confidence * 100,
              )}%)`
            : "none"}
        </p>
      )}
    </li>
  );
}
