// Test cases for frontend.yml (`semgrep --test scanning/semgrep`). Not compiled or bundled.
/* eslint-disable */

export async function calls(path: string) {
  // ruleid: sentineledge-fetch-outside-api-client
  await fetch(path);
  // ruleid: sentineledge-fetch-outside-api-client
  await window.fetch("/api/v1/health");
  // ruleid: sentineledge-fetch-outside-api-client
  const xhr = new XMLHttpRequest();
  return xhr;
}

export function storage(token: string) {
  // ruleid: sentineledge-web-storage
  localStorage.setItem("token", token);
  // ruleid: sentineledge-web-storage
  sessionStorage.getItem("token");
  // ok: sentineledge-web-storage
  const inMemory = new Map<string, string>([["token", token]]);
  return inMemory;
}

export function Evidence({ snippet }: { snippet: string }) {
  // ruleid: sentineledge-raw-html
  const unsafe = <div dangerouslySetInnerHTML={{ __html: snippet }} />;
  // ok: sentineledge-raw-html
  const safe = <code>{snippet}</code>;
  return [unsafe, safe];
}

export function dom(el: HTMLElement, html: string) {
  // ruleid: sentineledge-raw-html
  el.innerHTML = html;
  // ok: sentineledge-raw-html
  el.textContent = html;
}

export function dynamic(source: string) {
  // ruleid: sentineledge-dynamic-code
  eval(source);
  // ruleid: sentineledge-dynamic-code
  const f = new Function(source);
  return f;
}

export function Styled() {
  // ruleid: sentineledge-inline-style
  const inline = <span style={{ color: "red" }}>x</span>;
  // ok: sentineledge-inline-style
  const classes = <span className="text-fail">x</span>;
  return [inline, classes];
}

export function navigate(next: string) {
  // ruleid: sentineledge-navigation-to-variable
  window.location.href = next;
  // ruleid: sentineledge-navigation-to-variable
  window.location.assign(next);
  // ok: sentineledge-navigation-to-variable
  window.location.assign("/login");
}
