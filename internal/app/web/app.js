"use strict";
const $ = id => document.getElementById(id);
let csrf = "", user = null, subnets = [], selected = null, gridNext = "", gridStart = "", pendingChange = "", importPreview = "";
let noticeTimer;
let scopeImport = [];
function el(tag, text, cls) { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; }
function notice(text, error = false) { const n = $("notice"); n.textContent = text; n.className = error ? "error" : ""; n.hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => n.hidden = true, error ? 14000 : 6000); }
function safe(fn) { return async event => { try { await fn(event); } catch (e) { notice(e.message, true); } }; }
function on(id, event, fn) { $(id).addEventListener(event, safe(fn)); }
function formData(form) { return Object.fromEntries(new FormData(form)); }
function field(form, name) { return form.elements.namedItem(name); }
function fill(form, data) { form.reset(); for (const [key, value] of Object.entries(data)) { const f = field(form, key); if (!f) continue; if (f.type === "checkbox") f.checked = !!value; else f.value = value ?? ""; } }
function pretty(id, value) { $(id).textContent = JSON.stringify(value, null, 2); }
async function api(path, method = "GET", body) {
  const response = await fetch(path, { method, credentials: "same-origin", headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf }, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await response.text();
  let result; try { result = text ? JSON.parse(text) : {}; } catch { throw new Error(`Unexpected server response (${response.status})`); }
  if (!response.ok) {
    if (response.status === 401 && path !== "/api/login") showLogin();
    throw new Error(result.error || `Request failed (${response.status})`);
  }
  return result;
}
function showLogin() { user = null; csrf = ""; $("shell").hidden = true; $("login").hidden = false; document.querySelectorAll("dialog[open]").forEach(d => d.close()); }
function permissions() {
  document.querySelectorAll("[data-admin]").forEach(n => n.hidden = user?.role !== "admin");
  document.querySelectorAll("[data-write]").forEach(n => n.hidden = !["admin", "operator"].includes(user?.role));
}
async function init() {
  const auth = await api("/api/auth");
  if (auth.ldap) { const option = el("option", "Active Directory (LDAPS)"); option.value = "ldap"; $("login-method").append(option); }
  for (const name of ["oidc", "saml"]) if (auth[name]) { const a = el("a", `Sign in with ${name.toUpperCase()}`, "button"); a.href = `/auth/${name}/login`; $("sso-links").append(a); }
  try { await enter(); } catch { showLogin(); }
}
async function enter() {
  const me = await api("/api/me"); user = me.user; csrf = me.csrf;
  $("identity").textContent = `${user.name} · ${user.role}`; $("login").hidden = true; $("shell").hidden = false; permissions();
  await page("networks");
}
on("login-form", "submit", async e => { e.preventDefault(); const f = e.currentTarget; await api("/api/login", "POST", formData(f)); f.reset(); await enter(); });
on("logout", "click", async () => { await api("/api/logout", "POST", {}); showLogin(); });
document.querySelectorAll("[data-page]").forEach(b => b.addEventListener("click", safe(() => page(b.dataset.page))));
document.querySelectorAll("[data-close]").forEach(b => b.addEventListener("click", () => $(b.dataset.close).close()));
async function page(name) {
  document.querySelectorAll(".page").forEach(n => n.hidden = n.id !== `page-${name}`);
  document.querySelectorAll("[data-page]").forEach(n => { const active = n.dataset.page === name; n.classList.toggle("active", active); if (active) $("breadcrumb").textContent = n.textContent; });
  if (name === "networks") await loadSubnets();
  if (name === "jobs") await loadJobs();
  if (name === "audit") await loadAudit();
  if (name === "admin") { await loadUsers(); pretty("service-status", await api("/api/status")); }
  if (name === "integrations") await loadProviders();
}
async function loadSubnets() {
  subnets = await api("/api/subnets"); renderSubnets();
  $("stats").replaceChildren();
  for (const [label, value] of [["Managed subnets", subnets.length], ["Sites", new Set(subnets.map(s => s.site)).size], ["Scan-enabled networks", subnets.filter(s => s.scan_enabled).length]]) {
    const card = el("div", undefined, "stat"); card.append(el("span", label), el("strong", value)); $("stats").append(card);
  }
  if (selected) { selected = subnets.find(s => s.id === selected.id) || null; if (selected) await loadGrid(gridStart); }
  if (!selected && subnets.length) { selected = subnets[0]; await loadGrid(); }
  $("empty-subnet").hidden = !!selected; $("subnet-detail").hidden = !selected;
}
function renderSubnets() {
  const query = $("subnet-search").value.toLowerCase(); $("subnet-list").replaceChildren();
  for (const s of subnets.filter(s => `${s.name} ${s.cidr} ${s.site} ${s.vrf}`.toLowerCase().includes(query))) {
    const b = el("button", undefined, `subnet-item${selected?.id === s.id ? " active" : ""}`);
    b.append(el("strong", s.name), el("code", s.cidr), el("span", `${s.site} · ${s.vrf || "default VRF"}${s.vlan ? ` · VLAN ${s.vlan}` : ""}`));
    b.addEventListener("click", safe(async () => { selected = s; await loadGrid(); renderSubnets(); })); $("subnet-list").append(b);
  }
}
on("subnet-search", "input", renderSubnets); on("reload-subnets", "click", loadSubnets);
const stateLabels = { available: "Available", static: "Static", reserved: "Reserved", leased: "Leased", excluded: "Excluded", conflict: "Conflict", unknown: "Unknown", stale: "Stale", network: "Network" };
for (const [key, label] of Object.entries(stateLabels)) $("legend").append(el("span", label, `state-${key}`));
async function loadGrid(start = "") {
  if (!selected) return;
  const id = selected.id; const data = await api(`/api/subnets/${id}/addresses?limit=256&start=${encodeURIComponent(start)}`);
  if (selected?.id !== id) return;
  selected = data.subnet; gridNext = data.next; gridStart = start; $("grid-start").value = start;
  $("empty-subnet").hidden = true; $("subnet-detail").hidden = false; $("subnet-title").textContent = `${selected.name} · ${selected.cidr}`;
  $("subnet-meta").textContent = `${selected.site} / ${selected.vrf || "default"} · ${selected.description || "No description"}`;
  $("scan-subnet").disabled = !selected.scan_enabled;
  $("address-grid").replaceChildren();
  for (const address of data.addresses) {
    const state = address.display_state || address.state;
    const last = address.ip.includes(":") ? address.ip.split(":").pop() || "::" : address.ip.split(".").pop();
    const b = el("button", last, `ip-cell state-${stateLabels[state] ? state : "unknown"}${address.reachability === "reachable" ? " reachable" : ""}`);
    b.title = `${address.ip} · ${state} · ${address.hostname || "unnamed"} · ${address.reachability}`;
    b.setAttribute("aria-label", b.title); b.disabled = state === "network";
    b.addEventListener("click", () => editAddress(address)); $("address-grid").append(b);
  }
  if (!data.addresses.length) $("address-grid").append(el("p", "No recorded addresses in this range. IPv6 networks use sparse inventory.", "muted"));
  $("grid-caption").textContent = `${data.addresses.length} addresses shown · ${data.recorded} inventory records${data.sparse ? " · sparse IPv6" : ""}`;
  $("next-grid").disabled = !gridNext; renderSubnets(); permissions();
}
on("jump-grid", "click", () => loadGrid($("grid-start").value.trim()));
on("next-grid", "click", () => loadGrid(gridNext));
function editSubnet(s = {}) {
  fill($("subnet-form"), { vlan: 0, version: 0, site: "HQ", ...s });
  field($("subnet-form"), "cidr").readOnly = !!s.id; field($("subnet-form"), "vrf").readOnly = !!s.id;
  $("subnet-form-title").textContent = s.id ? "Edit subnet" : "Create subnet"; $("subnet-dialog").showModal();
}
on("add-subnet", "click", () => editSubnet()); on("edit-subnet", "click", () => editSubnet(selected));
on("subnet-form", "submit", async e => {
  e.preventDefault(); const f = e.currentTarget, data = formData(f), id = data.id;
  data.vlan = Number(data.vlan || 0); data.version = Number(data.version || 0); data.scan_enabled = field(f, "scan_enabled").checked;
  selected = await api(`/api/subnets${id ? `/${id}` : ""}`, id ? "PUT" : "POST", data);
  $("subnet-dialog").close(); gridStart = ""; await loadSubnets(); notice("Subnet saved.");
});
on("import-scopes", "click", async () => { const site = prompt("Site for imported scopes:", "HQ"); if (!site) return; const vrf = prompt("Routing domain / VRF:", ""); if (vrf === null) return; $("import-data").value = JSON.stringify(scopeImport.map(s => ({...s, site, vrf})), null, 2); $("apply-import").disabled = true; importPreview = ""; await page("imports"); notice("Scope candidates loaded. Validate and preview before applying."); });
on("delete-subnet", "click", async () => {
  const confirmCIDR = prompt(`Deleting this subnet removes its inventory, not external DNS/DHCP data. Type ${selected.cidr} to confirm.`);
  if (confirmCIDR !== selected.cidr) return;
  await api(`/api/subnets/${selected.id}?confirm=${encodeURIComponent(confirmCIDR)}&version=${selected.version}`, "DELETE");
  selected = null; await loadSubnets(); notice("Subnet inventory removed.");
});
function editAddress(x = {}) {
  fill($("address-form"), { version: 0, state: "unknown", ...x }); field($("address-form"), "ip").readOnly = !!x.ip;
  $("delete-address").disabled = !x.version;
  $("address-observation").textContent = `Reachability: ${x.reachability || "unknown"} · Last seen: ${x.last_seen || "never"}${x.dhcp ? ` · DHCP: ${JSON.stringify(x.dhcp)}` : ""}`;
  permissions(); $("address-dialog").showModal();
}
on("add-address", "click", () => editAddress());
on("address-form", "submit", async e => {
  e.preventDefault(); const data = formData(e.currentTarget); data.version = Number(data.version || 0);
  await api(`/api/subnets/${selected.id}/addresses/${encodeURIComponent(data.ip)}`, "PUT", data);
  $("address-dialog").close(); await loadGrid(gridStart); notice("Address inventory saved.");
});
on("delete-address", "click", async () => {
  const data = formData($("address-form")); if (!confirm(`Remove inventory for ${data.ip}? Provider records are unaffected.`)) return;
  await api(`/api/subnets/${selected.id}/addresses/${encodeURIComponent(data.ip)}?version=${data.version}`, "DELETE");
  $("address-dialog").close(); await loadGrid(gridStart);
});
on("scan-subnet", "click", async () => {
  if (!confirm("Probe up to 256 addresses starting at the current grid position? Allocation state will not change.")) return;
  const result = await api(`/api/subnets/${selected.id}/scan`, "POST", { start: gridStart, limit: 256 });
  notice(`Scan queued (${result.targets} targets). View Activity & jobs for progress.`);
});
on("import-file", "change", async e => { const f = e.target.files[0]; if (!f) return; if (f.size > 1800000) throw new Error("Import file too large (maximum 1.8 MB)."); $("import-data").value = await f.text(); importPreview = ""; $("apply-import").disabled = true; });
on("import-data", "input", () => { importPreview = ""; $("apply-import").disabled = true; });
function importBody(apply) {
  const text = $("import-data").value.trim(); if (!text) throw new Error("Enter import data first.");
  if (text.startsWith("[") || text.startsWith("{")) { const data = JSON.parse(text); const items = Array.isArray(data) ? data : data.subnets; if (!Array.isArray(items)) throw new Error("Expected a subnet array."); return { subnets: items, apply }; }
  return { csv: text, apply };
}
on("preview-import", "click", async () => { const data = await api("/api/import/subnets", "POST", importBody(false)); pretty("import-result", data); importPreview = $("import-data").value; $("apply-import").disabled = false; });
on("apply-import", "click", async () => {
  if (importPreview !== $("import-data").value || !importPreview) throw new Error("Validate this import first.");
  if (!confirm("Create all previewed subnets?")) return;
  pretty("import-result", await api("/api/import/subnets", "POST", importBody(true))); importPreview = ""; $("apply-import").disabled = true; notice("Import completed.");
});
async function loadProviders() {
  const list = await api("/api/providers"); $("provider-select").replaceChildren(); $("provider-info").replaceChildren();
  const networks = await api("/api/subnets"); $("provider-subnet").replaceChildren();
  const empty = el("option", "Do not link"); empty.value = ""; $("provider-subnet").append(empty);
  for (const n of networks) { const option = el("option", `${n.name} · ${n.cidr} · ${n.vrf || "default"}`); option.value = n.id; $("provider-subnet").append(option); }
  if (!list.length) $("provider-info").append(el("p", "No providers configured. Add a Windows connector, Kea, PowerDNS, or BIND entry to your server configuration, then restart.", "muted"));
  for (const p of list) { const option = el("option", `${p.id} (${p.kind})`); option.value = p.id; $("provider-select").append(option); $("provider-info").append(el("p", `${p.id}: ${p.capabilities}. Writes ${p.writes ? "enabled" : "disabled"}.`, "small muted")); }
}
on("provider-form", "input", () => { pendingChange = ""; $("confirm-provider").hidden = true; });
on("provider-form", "submit", async e => {
  e.preventDefault(); const data = formData(e.currentTarget), provider = data.provider; delete data.provider;
  const link = data.link_subnet; delete data.link_subnet;
  if (!provider) throw new Error("Configure a provider first.");
  data.ttl = Number(data.ttl || 0); data.subnet_id = Number(data.subnet_id || 0);
  const result = await api(`/api/providers/${encodeURIComponent(provider)}/${data.action === "read" ? "read" : "preview"}${data.action === "read" && link ? `?subnet=${encodeURIComponent(link)}` : ""}`, "POST", data);
  pretty("provider-result", result); pendingChange = result.job_id || ""; $("confirm-provider").hidden = !pendingChange;
  scopeImport = result.suggested_subnets || []; $("import-scopes").hidden = !scopeImport.length;
});
on("confirm-provider", "click", async () => {
  if (!pendingChange || !confirm("Apply the previewed change to the external server?")) return;
  await api(`/api/jobs/${pendingChange}/confirm`, "POST", { confirm: pendingChange }); pendingChange = ""; $("confirm-provider").hidden = true; notice("Change queued. Check Activity & jobs for the verified outcome.");
});
on("load-observations", "click", async () => pretty("observations", await api("/api/observations")));
on("neighbor-form", "submit", async e => { e.preventDefault(); pretty("neighbors", await api("/api/discovery/neighbors", "POST", formData(e.currentTarget))); });
function table(container, headers, rows) {
  const t = el("table"), head = el("thead"), hr = el("tr"), body = el("tbody");
  for (const h of headers) hr.append(el("th", h)); head.append(hr);
  for (const row of rows) { const tr = el("tr"); for (const value of row) { const td = el("td"); if (value instanceof Node) td.append(value); else td.textContent = value ?? ""; tr.append(td); } body.append(tr); }
  t.append(head, body); $(container).replaceChildren(t);
}
function details(value) { const d = el("details"); d.append(el("summary", "Details"), el("pre", typeof value === "string" ? value : JSON.stringify(value, null, 2))); return d; }
async function loadJobs() {
  const jobs = await api("/api/jobs");
  table("jobs", ["Created", "Type / target", "Status", "Result", ""], jobs.map(j => {
    const controls = el("div");
    if (["queued", "preview"].includes(j.status)) { const b = el("button", "Cancel"); b.addEventListener("click", safe(async () => { await api(`/api/jobs/${j.id}/cancel`, "POST", {}); await loadJobs(); })); controls.append(b); }
    return [j.created, `${j.kind} / ${j.target}`, j.status, details(j.result || j.payload), controls];
  }));
}
on("reload-jobs", "click", loadJobs);
async function loadAudit() { const rows = await api("/api/audit"); table("audit", ["Time", "Actor", "Action", "Target", "Detail"], rows.map(x => [x.time, x.actor, x.action, x.target, details(x.detail)])); }
on("reload-audit", "click", loadAudit);
async function loadUsers() {
  const users = await api("/api/users");
  table("users", ["Name", "Role", "Sites", "Status", ""], users.map(u => {
    const b = el("button", "Edit"); b.addEventListener("click", () => { fill($("user-form"), { ...u, sites: (u.sites || []).join(", "), password: "" }); field($("user-form"), "name").readOnly = true; });
    return [u.name, u.role, (u.sites || []).join(", "), u.disabled ? "Disabled" : "Enabled", b];
  }));
}
on("user-form", "submit", async e => {
  e.preventDefault(); const form = e.currentTarget; const data = formData(form); data.sites = data.sites.split(",").map(x => x.trim()).filter(Boolean); data.disabled = field(form, "disabled").checked;
  await api(`/api/users${data.id ? `/${data.id}` : ""}`, data.id ? "PUT" : "POST", data);
  form.reset(); field(form, "id").value = ""; field(form, "name").readOnly = false; await loadUsers(); notice("User saved. Existing sessions for this user were revoked.");
});
on("reset-user", "click", () => { $("user-form").reset(); field($("user-form"), "id").value = ""; field($("user-form"), "name").readOnly = false; });
on("backup", "click", async () => { const result = await api("/api/backups", "POST", {}); notice(`${result.file}: ${result.message}`); });
init().catch(e => notice(e.message, true));
