export function Logo({ size = 28 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <path d="M10.6 28.5a22 22 0 0 1 42.8 0" stroke="currentColor" strokeWidth="5" />
      <path d="M53.4 35.5a22 22 0 0 1-42.8 0" stroke="currentColor" strokeWidth="5" />
      <circle cx="32" cy="32" r="5.5" fill="currentColor" />
    </svg>
  );
}

export function LevelBadge({ level, label, testId }) {
  const value = level || "unknown";
  return (
    <span className={`level level-${value}`} data-testid={testId} data-level={value}>
      {label ? `${label} ` : ""}
      {value}
    </span>
  );
}

export function Spinner() {
  return <span className="spinner" aria-hidden="true" />;
}

export function seconds(value) {
  if (value == null) return "";
  if (value < 10) return `${value.toFixed(1)}s`;
  if (value < 60) return `${Math.round(value)}s`;
  return `${Math.floor(value / 60)}m ${Math.round(value % 60)}s`;
}

export function humanize(value) {
  return String(value || "").replace(/_/g, " ");
}
