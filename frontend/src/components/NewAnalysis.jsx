import { useEffect, useMemo, useRef, useState } from "react";
import { createAnalysis, getVersions, uploadProject } from "../api.js";
import { Spinner } from "./bits.jsx";

const NAME_PATTERN = /^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$/;

export default function NewAnalysis({ onSubmitted }) {
  const [project, setProject] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState(null);
  const [dragging, setDragging] = useState(false);

  const [packageName, setPackageName] = useState("");
  const [current, setCurrent] = useState("");
  const [target, setTarget] = useState("");
  const [versions, setVersions] = useState(null);
  const [versionState, setVersionState] = useState("idle");
  const [versionError, setVersionError] = useState(null);
  const [showPre, setShowPre] = useState(false);

  const [submitting, setSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState(null);
  const [notice, setNotice] = useState(null);

  const fileInput = useRef(null);
  const lookup = useRef(0);

  async function handleFile(file) {
    if (!file) return;
    setUploadError(null);
    setNotice(null);
    if (!file.name.toLowerCase().endsWith(".zip")) {
      setUploadError("Upload a .zip archive of the project.");
      return;
    }
    setUploading(true);
    try {
      const uploaded = await uploadProject(file);
      setProject(uploaded);
      const first = uploaded.dependencies[0];
      choosePackage(first?.name || "", first?.pinned_version || "");
    } catch (error) {
      setUploadError(error.message);
    } finally {
      setUploading(false);
      if (fileInput.current) fileInput.current.value = "";
    }
  }

  function choosePackage(name, pinned) {
    setPackageName(name);
    setCurrent(pinned || "");
    setTarget("");
    setSubmitError(null);
    setNotice(null);
  }

  function reset() {
    setProject(null);
    setPackageName("");
    setCurrent("");
    setTarget("");
    setVersions(null);
    setVersionState("idle");
    setSubmitError(null);
    setNotice(null);
  }

  // Look the package up on PyPI a moment after the name stops changing.
  const trimmedName = packageName.trim();
  useEffect(() => {
    const ticket = ++lookup.current;
    setVersions(null);
    setVersionError(null);
    if (!project || !trimmedName || !NAME_PATTERN.test(trimmedName)) {
      setVersionState("idle");
      return undefined;
    }
    setVersionState("loading");
    const timer = setTimeout(async () => {
      try {
        const result = await getVersions(trimmedName);
        if (ticket !== lookup.current) return;
        setVersions(result.versions);
        setVersionState("ready");
      } catch (error) {
        if (ticket !== lookup.current) return;
        setVersionError(error.message);
        setVersionState("error");
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [project, trimmedName]);

  // The list arrives newest first, so "newer than current" is a prefix.
  const visible = useMemo(
    () =>
      (versions || []).filter(
        (item) =>
          showPre || !item.prerelease || item.version === current || item.version === target,
      ),
    [versions, showPre, current, target],
  );
  const currentIndex = visible.findIndex((item) => item.version === current);
  const targetOptions = currentIndex === -1 ? visible : visible.slice(0, currentIndex);

  // Default the target to the newest stable release above the current one.
  useEffect(() => {
    if (versionState !== "ready" || !current || target) return;
    const index = (versions || []).findIndex((item) => item.version === current);
    if (index <= 0) return;
    const newer = versions.slice(0, index);
    const pick =
      newer.find((item) => !item.prerelease && !item.yanked) ||
      newer.find((item) => !item.prerelease) ||
      newer[0];
    if (pick) setTarget(pick.version);
  }, [versionState, versions, current, target]);

  const manual = versionState === "error";
  const canSubmit =
    project && trimmedName && current && target && current !== target && !submitting;

  async function submit(event) {
    event.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setSubmitError(null);
    setNotice(null);
    try {
      const job = await createAnalysis({
        project_id: project.id,
        package_name: trimmedName,
        current_version: current.trim(),
        target_version: target.trim(),
      });
      if (job.reused) setNotice("Already analyzed. Showing the existing result.");
      onSubmitted(job);
    } catch (error) {
      setSubmitError(error.message);
    } finally {
      setSubmitting(false);
    }
  }

  if (!project) {
    return (
      <div className="card">
        <div className="card-head">
          <h2>New analysis</h2>
        </div>
        <label
          className={`dropzone ${dragging ? "dropzone-active" : ""}`}
          data-testid="dropzone"
          onDragOver={(event) => {
            event.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            handleFile(event.dataTransfer.files?.[0]);
          }}
        >
          <input
            ref={fileInput}
            type="file"
            accept=".zip,application/zip"
            data-testid="file-input"
            onChange={(event) => handleFile(event.target.files?.[0])}
          />
          {uploading ? (
            <span className="dropzone-text">
              <Spinner /> Reading project…
            </span>
          ) : (
            <>
              <span className="dropzone-title">Drop a project .zip</span>
              <span className="dropzone-text">or click to choose a file</span>
            </>
          )}
        </label>
        {uploadError && (
          <p className="error" role="alert" data-testid="upload-error">
            {uploadError}
          </p>
        )}
        <p className="hint">
          Your code is read, never run. Up to 25 MB; uploads are deleted after an hour.
        </p>
      </div>
    );
  }

  return (
    <form className="card" onSubmit={submit} data-testid="analysis-form">
      <div className="card-head">
        <h2>New analysis</h2>
        <button type="button" className="link" onClick={reset} data-testid="replace-project">
          Change project
        </button>
      </div>

      <div className="project" data-testid="project">
        <span className="mono project-name">{project.name}</span>
        <span className="muted">
          {project.source_files} source · {project.test_files} test
          {project.test_files === 1 ? " file" : " files"}
        </span>
      </div>
      {project.warnings.map((warning) => (
        <p className="note" key={warning}>
          {warning}
        </p>
      ))}

      {project.dependencies.length > 0 && (
        <div className="field">
          <span className="label">Declared dependencies</span>
          <div className="deps">
            {project.dependencies.map((dependency) => (
              <button
                type="button"
                key={dependency.name}
                className={`dep ${
                  dependency.name.toLowerCase() === trimmedName.toLowerCase() ? "dep-on" : ""
                }`}
                data-testid="dependency"
                onClick={() => choosePackage(dependency.name, dependency.pinned_version)}
              >
                <span className="mono">{dependency.name}</span>
                {dependency.specifier && (
                  <span className="dep-spec mono">{dependency.specifier}</span>
                )}
              </button>
            ))}
          </div>
        </div>
      )}

      <label className="field">
        <span className="label">Package</span>
        <input
          className="input mono"
          value={packageName}
          placeholder="e.g. pandas"
          spellCheck={false}
          autoComplete="off"
          data-testid="package-input"
          onChange={(event) => choosePackage(event.target.value, "")}
        />
      </label>

      <div className="row">
        <label className="field">
          <span className="label">Current</span>
          {manual ? (
            <input
              className="input mono"
              value={current}
              placeholder="1.5.3"
              data-testid="current-version"
              onChange={(event) => setCurrent(event.target.value)}
            />
          ) : (
            <select
              className="input mono"
              value={current}
              disabled={versionState !== "ready"}
              data-testid="current-version"
              onChange={(event) => {
                setCurrent(event.target.value);
                setTarget("");
              }}
            >
              <option value="">{versionState === "loading" ? "Loading…" : "Select"}</option>
              {current && !visible.some((item) => item.version === current) && (
                <option value={current}>{current}</option>
              )}
              {visible.map((item) => (
                <option key={item.version} value={item.version}>
                  {item.version}
                  {item.yanked ? " (yanked)" : ""}
                </option>
              ))}
            </select>
          )}
        </label>
        <span className="arrow" aria-hidden="true">
          →
        </span>
        <label className="field">
          <span className="label">Target</span>
          {manual ? (
            <input
              className="input mono"
              value={target}
              placeholder="2.0.0"
              data-testid="target-version"
              onChange={(event) => setTarget(event.target.value)}
            />
          ) : (
            <select
              className="input mono"
              value={target}
              disabled={versionState !== "ready" || !current}
              data-testid="target-version"
              onChange={(event) => setTarget(event.target.value)}
            >
              <option value="">
                {versionState === "loading"
                  ? "Loading…"
                  : current && targetOptions.length === 0
                    ? "No newer release"
                    : "Select"}
              </option>
              {targetOptions.map((item) => (
                <option key={item.version} value={item.version}>
                  {item.version}
                  {item.yanked ? " (yanked)" : ""}
                </option>
              ))}
            </select>
          )}
        </label>
      </div>

      {versionState === "ready" && (
        <label className="check">
          <input
            type="checkbox"
            checked={showPre}
            onChange={(event) => setShowPre(event.target.checked)}
          />
          Include pre-releases
        </label>
      )}
      {manual && (
        <p className="note" data-testid="version-error">
          {versionError} Enter the versions by hand.
        </p>
      )}

      <button type="submit" className="primary" disabled={!canSubmit} data-testid="analyze">
        {submitting ? "Queuing…" : "Analyze upgrade"}
      </button>
      {submitError && (
        <p className="error" role="alert" data-testid="submit-error">
          {submitError}
        </p>
      )}
      {notice && (
        <p className="note" data-testid="notice">
          {notice}
        </p>
      )}
    </form>
  );
}
