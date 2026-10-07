import type { Capability } from "../lib/types";

export const CAPS: Capability[] = [
  { key: "platform.health", name: "Health endpoint", area: "Platform", provenance: "LOCAL", status: "implemented", phase: 1, note: "Local." },
  { key: "aws.waf", name: "AWS WAF on CloudFront", area: "WAF", provenance: "REAL_AWS", status: "planned", phase: 5, note: "Terraform." },
  { key: "sim.waf_toggle", name: "In-dashboard WAF rule toggling", area: "WAF", provenance: "SIMULATED", status: "planned", phase: 7, note: "Simulation only." },
];

export function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function mockApi(routes: Record<string, () => Response>) {
  return (input: RequestInfo | URL) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.pathname : input.url;
    const handler = routes[url];
    return Promise.resolve(handler ? handler() : jsonResponse({ error: { code: "not_found", message: "Not Found" } }, 404));
  };
}
