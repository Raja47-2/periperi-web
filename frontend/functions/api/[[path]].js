const BACKEND = "http://187.127.140.188:8000";

const SCAN_ID = /^[0-9a-fA-F-]{1,64}$/;

const ROUTES = [
  { pattern: /^\/health$/, methods: ["GET", "HEAD"] },
  { pattern: /^\/scans$/, methods: ["GET", "HEAD"] },
  { pattern: /^\/scan$/, methods: ["POST"] },
  { pattern: /^\/scan\/sample$/, methods: ["POST"] },
  { pattern: /^\/scan\/([0-9a-fA-F-]{1,64})$/, methods: ["GET", "HEAD"] },
  { pattern: /^\/scan\/([0-9a-fA-F-]{1,64})\/report$/, methods: ["GET", "HEAD"] },
];

function matchRoute(pathname) {
  for (const route of ROUTES) {
    const match = pathname.match(route.pattern);
    if (match) return { route, params: match.slice(1) };
  }
  return null;
}

export async function onRequest({ request }) {
  const incoming = new URL(request.url);
  const backendPath = incoming.pathname.slice(4) || "/";

  const matched = matchRoute(backendPath);
  if (!matched) {
    return new Response("Not found", { status: 404 });
  }

  const method = request.method.toUpperCase();
  if (!matched.route.methods.includes(method)) {
    return new Response("Method not allowed", {
      status: 405,
      headers: { Allow: matched.route.methods.join(", ") },
    });
  }

  const target = new URL(BACKEND + backendPath);
  target.search = incoming.search;

  const headers = new Headers(request.headers);
  headers.delete("host");
  headers.delete("content-length");
  headers.delete("connection");
  headers.set("x-forwarded-proto", "https");
  headers.set("x-forwarded-host", incoming.host);

  const hasBody = method !== "GET" && method !== "HEAD";

  try {
    const response = await fetch(target.toString(), {
      method,
      headers,
      body: hasBody ? request.body : undefined,
      redirect: "manual",
      signal: AbortSignal.timeout(120000),
    });

    const outHeaders = new Headers(response.headers);
    // The runtime re-encodes the body, so upstream framing headers must be dropped.
    for (const header of ["content-length", "content-encoding", "transfer-encoding", "connection"]) {
      outHeaders.delete(header);
    }
    // Same-origin via Pages, so the browser needs no CORS grant.
    for (const header of ["access-control-allow-origin", "access-control-allow-credentials", "access-control-allow-methods", "access-control-allow-headers"]) {
      outHeaders.delete(header);
    }

    return new Response(response.body, {
      status: response.status,
      headers: outHeaders,
    });
  } catch (error) {
    const message =
      error && error.name === "TimeoutError"
        ? "The scan timed out. Try a smaller project or raise the timeout."
        : "The ECDAT backend is unreachable.";
    return Response.json({ detail: message }, { status: 502 });
  }
}
