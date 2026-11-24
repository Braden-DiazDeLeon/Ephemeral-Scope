// Thin wrapper over the JSON API. Every failure becomes an Error whose
// message is safe to show to the user.

async function request(path, options) {
  let response;
  try {
    response = await fetch(`/api${path}`, options);
  } catch {
    throw new Error("The analysis server is not reachable.");
  }
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  if (!response.ok) {
    throw new Error(errorMessage(body, response.status));
  }
  return body;
}

function errorMessage(body, status) {
  const detail = body?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => String(item.msg || "").replace(/^Value error, /, ""))
      .filter(Boolean)
      .join("; ");
  }
  if (status === 502 || status === 504) {
    return "The analysis server is not reachable.";
  }
  return `Request failed (${status}).`;
}

export function getHealth() {
  return request("/health");
}

export function uploadProject(file) {
  const form = new FormData();
  form.append("file", file);
  return request("/projects", { method: "POST", body: form });
}

export function getVersions(packageName) {
  return request(`/packages/${encodeURIComponent(packageName)}/versions`);
}

export function createAnalysis(payload) {
  return request("/analyses", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function listAnalyses(ids) {
  return request(`/analyses?ids=${encodeURIComponent(ids.join(","))}`);
}

export function getAnalysis(id) {
  return request(`/analyses/${encodeURIComponent(id)}`);
}
