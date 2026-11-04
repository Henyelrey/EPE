// Panel del puerto de administración. Todo lo que muestra se escribe como texto, nunca como HTML.
"use strict";

const REFRESH_MS = 5000;
const LOG_REFRESH_MS = 3000;
const TOKEN_KEY = "rayo-admin-token";

const ALERT_INFO = {
  disk_space: { title: "Poco espacio en el volumen", severity: "critical" },
  disk_limit: { title: "La caché pasó de su límite", severity: "critical" },
  corrupt_objects: { title: "Objetos corruptos", severity: "critical" },
  store_writes: { title: "Fallos al guardar en disco", severity: "critical" },
  ca_expiry: { title: "Certificado por vencer", severity: "warning" },
  origin_errors: { title: "Errores al contactar orígenes", severity: "warning" },
  detections: { title: "Actividad inusual", severity: "warning" },
};

const VIEW_TITLES = { resumen: "Resumen", registro: "Registro en vivo" };

const TRAFFIC_SERIES = [
  { key: "copy", id: "hit", name: "Desde copia" },
  { key: "stored", id: "miss", name: "Descargado y guardado" },
  { key: "bypass", id: "bypass", name: "Sin caché" },
];

const LIVE_RESULTS = {
  hit: { name: "Copia válida", swatch: "hit" },
  revalidated: { name: "Copia confirmada", swatch: "revalidated" },
  miss: { name: "Descargada y guardada", swatch: "miss" },
  bypass: { name: "Sin caché", swatch: "bypass" },
  origin_error: { name: "Error del origen", swatch: "error" },
  cache_error: { name: "Error de caché", swatch: "error" },
  blocked: { name: "Rechazada", swatch: "error" },
  tunnel: { name: "Túnel sin descifrar", swatch: "neutral" },
};

const DETECTION_TITLES = {
  volume: "Volumen alto",
  denied: "Muchos rechazos",
  rare_port: "Puerto no permitido",
  host_mismatch: "Nombre que no coincide",
};

const $ = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat("es");
const decimalFormat = new Intl.NumberFormat("es", { maximumFractionDigits: 1 });
const dateFormat = new Intl.DateTimeFormat("es", { dateStyle: "medium" });
const dateTimeFormat = new Intl.DateTimeFormat("es", { dateStyle: "short", timeStyle: "short" });
const timeFormat = new Intl.DateTimeFormat("es", { timeStyle: "medium" });
const logTimeFormat = new Intl.DateTimeFormat("es", { dateStyle: "short", timeStyle: "medium" });

function formatBytes(bytes) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${decimalFormat.format(value)} ${units[unit]}`;
}

function formatRate(bytesPerSecond) {
  const units = ["bps", "kbps", "Mbps", "Gbps"];
  let value = bytesPerSecond * 8;
  let unit = 0;
  while (value >= 1000 && unit < units.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return `${decimalFormat.format(value)} ${units[unit]}`;
}

function formatPercent(ratio) {
  return `${decimalFormat.format(ratio * 100)} %`;
}

function formatDuration(secs) {
  if (secs < 60) return `${secs} s`;
  if (secs < 3600) return `${Math.floor(secs / 60)} min`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h`;
  return `${Math.floor(secs / 86400)} d`;
}

function formatMs(ms) {
  return `${decimalFormat.format(ms)} ms`;
}

// El almacenamiento de la pestaña puede no estar disponible: entonces el token solo vive en memoria.
let memoryToken = null;
function loadToken() {
  try {
    return sessionStorage.getItem(TOKEN_KEY) || memoryToken;
  } catch {
    return memoryToken;
  }
}
function saveToken(token) {
  memoryToken = token;
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    // Queda solo en memoria.
  }
}

class Unauthorized extends Error {}

async function fetchJson(path) {
  const res = await fetch(path, { headers: { Authorization: `Bearer ${loadToken()}` }, cache: "no-store" });
  if (res.status === 401) throw new Unauthorized();
  if (!res.ok) throw new Error(`respuesta ${res.status}`);
  return res.json();
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderAlerts(alerts) {
  const box = $("alerts");
  box.replaceChildren();
  if (alerts.length === 0) {
    const ok = element("div", "alert good");
    ok.append(element("span", "icon", "✓"), element("p", "title", "Sin alertas"));
    box.append(ok);
    return;
  }
  for (const alert of alerts) {
    const info = ALERT_INFO[alert.name] || { title: alert.name, severity: "critical" };
    const row = element("div", `alert ${info.severity}`);
    const text = element("div");
    text.append(element("p", "title", info.title), element("p", "message", alert.message));
    row.append(element("span", "icon", "!"), text);
    box.append(row);
  }
}

function showTooltip(target, text) {
  const tip = $("tooltip");
  tip.textContent = text;
  tip.hidden = false;
  const box = target.getBoundingClientRect();
  const left = Math.min(box.left, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${Math.max(8, left)}px`;
  tip.style.top = `${box.bottom + 6}px`;
}

function hideTooltip() {
  $("tooltip").hidden = true;
}

function resultRows(summary) {
  const { results, latency } = summary;
  return [
    { id: "hit", name: "Copia válida", count: results.hit, latency: latency.hit },
    { id: "revalidated", name: "Copia confirmada por el origen", count: results.revalidated, latency: latency.revalidated },
    { id: "miss", name: "Descargada y guardada", count: results.miss, latency: latency.miss },
    { id: "bypass", name: "Sin caché", count: results.bypass, latency: latency.bypass },
    { id: "error", name: "Error", count: results.origin_error + results.cache_error, latency: latency.error },
  ];
}

function renderResults(summary) {
  const rows = resultRows(summary);
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  const bar = $("results-bar");
  $("results-empty").hidden = total > 0;
  bar.hidden = total === 0;
  bar.replaceChildren();
  $("results-legend").replaceChildren();
  $("results-table").replaceChildren();

  for (const row of rows) {
    const share = total > 0 ? row.count / total : 0;
    const description = `${row.name}: ${numberFormat.format(row.count)} (${formatPercent(share)})`;

    const legendItem = element("li");
    legendItem.append(element("span", `swatch ${row.id}`), document.createTextNode(row.name));
    $("results-legend").append(legendItem);

    const tr = element("tr");
    tr.append(
      element("td", "", row.name),
      element("td", "num", numberFormat.format(row.count)),
      element("td", "num", formatPercent(share)),
      element("td", "num", row.latency.count > 0 ? formatMs(row.latency.avg_ms) : "—"),
    );
    $("results-table").append(tr);

    if (row.count === 0) continue;
    const part = element("div", `segment ${row.id}`);
    part.style.flex = `${row.count} 1 0`;
    part.tabIndex = 0;
    part.setAttribute("role", "img");
    part.setAttribute("aria-label", description);
    part.addEventListener("mouseenter", () => showTooltip(part, description));
    part.addEventListener("focus", () => showTooltip(part, description));
    part.addEventListener("mouseleave", hideTooltip);
    part.addEventListener("blur", hideTooltip);
    const label = element("span", "", formatPercent(share));
    part.append(label);
    bar.append(part);
  }
  // La etiqueta solo se deja si cabe entera dentro de su bloque. El valor sigue en la tabla.
  for (const part of bar.children) {
    const label = part.firstChild;
    if (label.offsetWidth + 16 > part.clientWidth) label.remove();
  }
}

function setMeter(id, used, total, description) {
  const meter = $(id);
  meter.setAttribute("aria-label", description);
  meter.firstElementChild.style.width = total > 0 ? `${Math.min(100, (used / total) * 100)}%` : "0";
}

function fillDefinitions(id, entries) {
  const list = $(id);
  list.replaceChildren();
  for (const [term, value] of entries) {
    list.append(element("dt", "", term), element("dd", "", value));
  }
}

function renderDisk(disk) {
  const limit = disk.limit > 0 ? `de ${formatBytes(disk.limit)}` : "sin límite";
  const usage = `${formatBytes(disk.used)} ${limit}`;
  $("cache-usage").textContent = usage;
  setMeter("cache-meter", disk.used, disk.limit, `Caché: ${usage}`);
  const volumeKnown = disk.total > 0;
  const volume = volumeKnown ? `${formatBytes(disk.free)} libres de ${formatBytes(disk.total)}` : "sin medir todavía";
  $("volume-usage").textContent = volume;
  setMeter("volume-meter", disk.total - disk.free, disk.total, `Volumen: ${volume}`);
  fillDefinitions("disk-details", [
    ["Objetos guardados", numberFormat.format(disk.objects)],
    ["Entradas expulsadas por el límite", numberFormat.format(disk.evicted_entries)],
    ["Espacio liberado al expulsar", formatBytes(disk.evicted_bytes)],
  ]);
}

function renderSummary(summary) {
  renderAlerts(summary.alerts);
  $("saved").textContent = formatBytes(summary.bytes.cache);
  $("saved-note").textContent = `Desde el ${dateFormat.format(new Date(summary.since * 1000))}. Encendido hace ${formatDuration(summary.uptime_secs)}.`;
  $("byte-ratio").textContent = formatPercent(summary.byte_hit_ratio);
  $("request-ratio").textContent = formatPercent(summary.request_hit_ratio);
  $("requests").textContent = numberFormat.format(summary.requests);
  $("ca-expiry").textContent = dateFormat.format(new Date(summary.ca_not_after * 1000));
  renderResults(summary);
  renderDisk(summary.disk);
  fillDefinitions("health", [
    ["Bytes descargados y guardados", formatBytes(summary.bytes.origin)],
    ["Bytes sin caché", formatBytes(summary.bytes.bypass)],
    ["Conexiones descifradas", numberFormat.format(summary.tls.intercepted)],
    ["Túneles sin descifrar", numberFormat.format(summary.tls.passthrough)],
    ["Clientes rechazados", numberFormat.format(summary.rejections.client)],
    ["Peticiones sobre el límite por IP", numberFormat.format(summary.rejections.rate_limit)],
    ["Destinos internos bloqueados", numberFormat.format(summary.rejections.destination)],
    ["Túneles a puertos no permitidos", numberFormat.format(summary.rejections.port)],
    ["Atendidas sin caché por falta de memoria", numberFormat.format(summary.health.over_budget)],
    ["Objetos corruptos", numberFormat.format(summary.health.corrupt_objects)],
    ["Fallos al guardar en disco", numberFormat.format(summary.health.store_write_errors)],
    ["Líneas perdidas de los logs", numberFormat.format(summary.health.access_log_dropped + summary.health.access_log_errors)],
  ]);
}

function renderClients(data) {
  const clients = data.clients;
  $("clients-off").hidden = data.enabled;
  $("clients-empty").hidden = !data.enabled || clients.length > 0;
  $("clients-wrap").hidden = !data.enabled || clients.length === 0;
  const body = $("clients-table");
  body.replaceChildren();
  for (const client of clients) {
    const tr = element("tr");
    tr.append(
      element("td", "", client.ip),
      element("td", "num", numberFormat.format(client.requests)),
      element("td", "num", numberFormat.format(client.served_from_copy)),
      element("td", "num", formatBytes(client.bytes)),
      element("td", "num", numberFormat.format(client.tunnels)),
      element("td", "num", numberFormat.format(client.blocked + client.rate_limited)),
      element("td", "", dateTimeFormat.format(new Date(client.last_seen * 1000))),
    );
    body.append(tr);
  }
}

function renderDetections(data) {
  const events = data.events;
  $("detections-off").hidden = data.enabled;
  $("detections-empty").hidden = !data.enabled || events.length > 0;
  $("detections-wrap").hidden = events.length === 0;
  $("detections-note").hidden = !data.enabled;
  const body = $("detections-table");
  body.replaceChildren();
  for (const event of events) {
    const tr = element("tr");
    tr.append(
      element("td", "nowrap", DETECTION_TITLES[event.kind] || event.kind),
      element("td", "nowrap", event.ip),
      element("td", "num", numberFormat.format(event.count)),
      element("td", "nowrap", dateTimeFormat.format(new Date(event.last_seen * 1000))),
      element("td", "detail", event.detail),
    );
    body.append(tr);
  }
}

function svg(tag, attributes) {
  const node = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
}

// Tope redondeado del eje, en bits por segundo. Con poco tráfico no se amplifica el ruido.
function niceScale(bits) {
  const floor = Math.max(bits, 1e6);
  const power = 10 ** Math.floor(Math.log10(floor));
  const step = [1, 2, 5, 10].find((candidate) => floor <= candidate * power);
  return step * power;
}

let trafficData = null;
let chartGeometry = null;
let pointerX = null;

function renderTraffic(data) {
  trafficData = data;
  const points = data.points;
  const last = points[points.length - 1];
  const legend = $("traffic-legend");
  legend.replaceChildren();
  for (const series of TRAFFIC_SERIES) {
    const item = element("li");
    item.append(element("span", `swatch ${series.id}`), document.createTextNode(series.name));
    if (last) item.append(element("strong", "", formatRate(last[series.key])));
    legend.append(item);
  }
  const chart = $("traffic-chart");
  $("traffic-empty").hidden = points.length > 0;
  chart.hidden = points.length === 0;
  chart.replaceChildren();
  chartGeometry = null;
  if (!last) return;
  const summary = TRAFFIC_SERIES.map((series) => `${series.name}: ${formatRate(last[series.key])}`).join(". ");
  chart.setAttribute("aria-label", `Tráfico de los últimos 5 minutos. Ahora: ${summary}.`);

  const width = chart.clientWidth;
  const height = chart.clientHeight;
  if (width === 0 || height === 0) return;
  const box = { left: 72, right: width - 8, top: 8, bottom: height - 22 };
  // Las series se apilan: con líneas, dos valores iguales en el mismo instante se taparían.
  const peak = Math.max(...points.map((point) => TRAFFIC_SERIES.reduce((sum, series) => sum + point[series.key], 0) * 8));
  const scale = niceScale(peak);
  const xOf = (index) => box.right - ((points.length - 1 - index) / (data.capacity - 1)) * (box.right - box.left);
  const yOf = (bytesPerSecond) => box.bottom - ((bytesPerSecond * 8) / scale) * (box.bottom - box.top);

  const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, "aria-hidden": "true" });
  for (const fraction of [0, 0.5, 1]) {
    const y = box.bottom - fraction * (box.bottom - box.top);
    root.append(svg("line", { class: "grid-line", x1: box.left, x2: box.right, y1: y, y2: y }));
    const label = svg("text", { class: "axis-text", x: box.left - 8, y: y + 4, "text-anchor": "end" });
    label.textContent = formatRate((scale * fraction) / 8);
    root.append(label);
  }
  const oldest = svg("text", { class: "axis-text", x: box.left, y: height - 4 });
  oldest.textContent = "hace 5 min";
  const newest = svg("text", { class: "axis-text", x: box.right, y: height - 4, "text-anchor": "end" });
  newest.textContent = "ahora";
  root.append(oldest, newest);
  const below = points.map(() => 0);
  for (const series of TRAFFIC_SERIES) {
    const bottom = points.map((_, index) => `${xOf(index).toFixed(1)},${yOf(below[index]).toFixed(1)}`).reverse();
    const top = points.map((point, index) => {
      below[index] += point[series.key];
      return `${xOf(index).toFixed(1)},${yOf(below[index]).toFixed(1)}`;
    });
    root.append(svg("polygon", { class: `series ${series.id}`, points: [...top, ...bottom].join(" ") }));
  }
  chart.append(root);
  chartGeometry = { root, box, xOf, points };
  if (pointerX !== null) showChartPoint();
}

// Línea vertical y valores del punto más cercano al puntero.
function showChartPoint() {
  if (!chartGeometry) return;
  const { root, box, xOf, points } = chartGeometry;
  const bounds = root.getBoundingClientRect();
  const x = pointerX - bounds.left;
  let nearest = 0;
  points.forEach((_, index) => {
    if (Math.abs(xOf(index) - x) < Math.abs(xOf(nearest) - x)) nearest = index;
  });
  root.querySelector(".cursor")?.remove();
  root.append(svg("line", { class: "cursor", x1: xOf(nearest), x2: xOf(nearest), y1: box.top, y2: box.bottom }));
  const point = points[nearest];
  const lines = TRAFFIC_SERIES.map((series) => `${series.name}: ${formatRate(point[series.key])}`);
  const tip = $("tooltip");
  tip.textContent = [timeFormat.format(new Date(point.ts * 1000)), ...lines].join("\n");
  tip.hidden = false;
  const left = Math.min(bounds.left + xOf(nearest) + 12, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${Math.max(8, left)}px`;
  tip.style.top = `${bounds.top + 8}px`;
}

$("traffic-chart").addEventListener("mousemove", (event) => {
  pointerX = event.clientX;
  showChartPoint();
});
$("traffic-chart").addEventListener("mouseleave", () => {
  pointerX = null;
  chartGeometry?.root.querySelector(".cursor")?.remove();
  hideTooltip();
});
window.addEventListener("resize", () => {
  if (trafficData && currentView() === "registro") renderTraffic(trafficData);
});

let liveData = null;
let livePaused = false;

for (const [value, info] of [["", { name: "Todos" }], ...Object.entries(LIVE_RESULTS)]) {
  const option = element("option", "", info.name);
  option.value = value;
  $("live-result").append(option);
}

function domainLabel(entry) {
  const standardPort = entry.port === null || entry.port === 80 || entry.port === 443;
  return standardPort ? entry.host : `${entry.host}:${entry.port}`;
}

function liveMatches(entry, result, text) {
  if (result && entry.result !== result) return false;
  if (!text) return true;
  return [domainLabel(entry), entry.path || "", entry.client || ""].some((field) => field.toLowerCase().includes(text));
}

function renderLive() {
  if (!liveData) return;
  const { enabled, client, capacity, entries } = liveData;
  $("live-off").hidden = enabled;
  $("live-controls").hidden = !enabled;
  $("live-note").hidden = !enabled;
  const showClient = client !== "none";
  $("live-client-head").hidden = !showClient;
  $("live-client-head").textContent = client === "ip" ? "IP" : "Cliente";

  const result = $("live-result").value;
  const text = $("live-filter").value.trim().toLowerCase();
  const matching = entries.filter((entry) => liveMatches(entry, result, text));
  const rows = matching.slice(0, Number($("live-limit").value));
  const body = $("live-table");
  body.replaceChildren();
  for (const entry of rows) {
    const info = LIVE_RESULTS[entry.result] || { name: entry.result, swatch: "neutral" };
    const tr = element("tr");
    tr.title = `${entry.method}${entry.status === null ? "" : ` · respuesta ${entry.status}`}`;
    tr.append(element("td", "nowrap", logTimeFormat.format(new Date(entry.ts * 1000))));
    if (showClient) tr.append(element("td", "nowrap", entry.client));
    const outcome = element("span", "result");
    outcome.append(element("span", `swatch ${info.swatch}`), document.createTextNode(info.name));
    const outcomeCell = element("td");
    outcomeCell.append(outcome);
    const object = element("td", "object", entry.path || "—");
    if (entry.path) object.title = entry.path;
    tr.append(
      outcomeCell,
      element("td", "", domainLabel(entry)),
      object,
      element("td", "num", entry.bytes === null ? "—" : formatBytes(entry.bytes)),
      element("td", "num", formatMs(entry.ms)),
    );
    body.append(tr);
  }
  $("live-wrap").hidden = !enabled || rows.length === 0;
  $("live-empty").hidden = !enabled || rows.length > 0;
  $("live-empty").textContent = entries.length > 0 ? "Ninguna coincide con el filtro." : "Todavía no hay peticiones.";
  $("live-count").hidden = !enabled || rows.length === 0;
  $("live-count").textContent = `Mostrando ${numberFormat.format(rows.length)} de ${numberFormat.format(matching.length)}. En memoria se guardan las últimas ${numberFormat.format(capacity)}.`;
}

for (const id of ["live-result", "live-limit", "live-filter"]) {
  $(id).addEventListener("input", renderLive);
}

$("live-pause").addEventListener("click", () => {
  livePaused = !livePaused;
  $("live-pause").setAttribute("aria-pressed", String(livePaused));
  $("live-pause").textContent = livePaused ? "Reanudar" : "Pausar";
  if (!livePaused) refresh();
});

function currentView() {
  return location.hash === "#registro" ? "registro" : "resumen";
}

function applyView() {
  const view = currentView();
  $("dashboard").hidden = view !== "resumen";
  $("log-view").hidden = view !== "registro";
  $("page-title").textContent = VIEW_TITLES[view];
  for (const link of document.querySelectorAll(".nav-link")) {
    if (link.dataset.view === view) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  hideTooltip();
}

function renderService(summary) {
  $("service-dot").classList.remove("down");
  $("service-text").textContent = `Funcionando. Encendido hace ${formatDuration(summary.uptime_secs)}.`;
  const count = summary.alerts.length;
  $("alert-badge").hidden = count === 0;
  $("alert-badge").textContent = numberFormat.format(count);
  $("alert-badge").setAttribute("aria-label", count === 1 ? "1 alerta" : `${count} alertas`);
}

function setStale(stale) {
  $("dashboard").classList.toggle("stale", stale);
  $("log-view").classList.toggle("stale", stale);
}

function showLogin(message) {
  $("dashboard").hidden = true;
  $("log-view").hidden = true;
  $("sidebar").hidden = true;
  $("page-title").textContent = "Panel de rayo-cache";
  $("logout").hidden = true;
  $("freshness").textContent = "";
  $("login").hidden = false;
  $("login-error").hidden = !message;
  $("login-error").textContent = message || "";
  $("token").focus();
}

let timer = null;

function showDashboard(summary) {
  $("login").hidden = true;
  $("logout").hidden = false;
  $("sidebar").hidden = false;
  applyView();
  setStale(false);
  renderService(summary);
}

async function refresh() {
  clearTimeout(timer);
  try {
    const view = currentView();
    if (view === "registro") {
      const [summary, traffic, live] = await Promise.all([fetchJson("/api/summary"), fetchJson("/api/traffic"), fetchJson("/api/live")]);
      showDashboard(summary);
      renderTraffic(traffic);
      if (!livePaused) {
        liveData = live;
        renderLive();
      }
    } else {
      const [summary, clients, detections] = await Promise.all([fetchJson("/api/summary"), fetchJson("/api/clients"), fetchJson("/api/detections")]);
      showDashboard(summary);
      renderSummary(summary);
      renderDetections(detections);
      renderClients(clients);
    }
    const paused = view === "registro" && livePaused ? " Tabla en pausa." : "";
    $("freshness").textContent = `Actualizado a las ${timeFormat.format(new Date())}.${paused}`;
  } catch (error) {
    if (error instanceof Unauthorized) {
      saveToken(null);
      showLogin("El token no es válido.");
      return;
    }
    // Se mantiene lo último que se mostró, atenuado, hasta poder actualizarlo.
    setStale(true);
    $("service-dot").classList.add("down");
    $("service-text").textContent = "Sin respuesta del proxy.";
    $("freshness").textContent = "No se pudo actualizar. Se reintentará en unos segundos.";
  }
  timer = setTimeout(refresh, currentView() === "registro" ? LOG_REFRESH_MS : REFRESH_MS);
}

$("login").addEventListener("submit", (event) => {
  event.preventDefault();
  saveToken($("token").value.trim());
  $("token").value = "";
  refresh();
});

$("logout").addEventListener("click", () => {
  clearTimeout(timer);
  saveToken(null);
  showLogin("");
});

window.addEventListener("hashchange", () => {
  if (!loadToken()) return;
  applyView();
  refresh();
});

if (loadToken()) refresh();
else showLogin("");
