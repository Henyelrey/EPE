// Panel del puerto de administración. Todo lo que muestra se escribe como texto, nunca como HTML.
"use strict";

const REFRESH_MS = 5000;
const TOKEN_KEY = "rayo-admin-token";

const ALERT_INFO = {
  disk_space: { title: "Poco espacio en el volumen", severity: "critical" },
  disk_limit: { title: "La caché pasó de su límite", severity: "critical" },
  corrupt_objects: { title: "Objetos corruptos", severity: "critical" },
  store_writes: { title: "Fallos al guardar en disco", severity: "critical" },
  ca_expiry: { title: "Certificado por vencer", severity: "warning" },
  origin_errors: { title: "Errores al contactar orígenes", severity: "warning" },
};

const $ = (id) => document.getElementById(id);
const numberFormat = new Intl.NumberFormat("es");
const decimalFormat = new Intl.NumberFormat("es", { maximumFractionDigits: 1 });
const dateFormat = new Intl.DateTimeFormat("es", { dateStyle: "medium" });
const dateTimeFormat = new Intl.DateTimeFormat("es", { dateStyle: "short", timeStyle: "short" });
const timeFormat = new Intl.DateTimeFormat("es", { timeStyle: "medium" });

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
    ["Atendidas sin caché por falta de memoria", numberFormat.format(summary.health.over_budget)],
    ["Objetos corruptos", numberFormat.format(summary.health.corrupt_objects)],
    ["Fallos al guardar en disco", numberFormat.format(summary.health.store_write_errors)],
    ["Líneas perdidas del log de acceso", numberFormat.format(summary.health.access_log_dropped + summary.health.access_log_errors)],
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

function showLogin(message) {
  $("dashboard").hidden = true;
  $("logout").hidden = true;
  $("freshness").textContent = "";
  $("login").hidden = false;
  $("login-error").hidden = !message;
  $("login-error").textContent = message || "";
  $("token").focus();
}

let timer = null;

async function refresh() {
  clearTimeout(timer);
  try {
    const [summary, clients] = await Promise.all([fetchJson("/api/summary"), fetchJson("/api/clients")]);
    $("login").hidden = true;
    $("logout").hidden = false;
    $("dashboard").hidden = false;
    $("dashboard").classList.remove("stale");
    renderSummary(summary);
    renderClients(clients);
    $("freshness").textContent = `Actualizado a las ${timeFormat.format(new Date())}`;
  } catch (error) {
    if (error instanceof Unauthorized) {
      saveToken(null);
      showLogin("El token no es válido.");
      return;
    }
    // Se mantiene lo último que se mostró, atenuado, hasta poder actualizarlo.
    $("dashboard").classList.add("stale");
    $("freshness").textContent = "No se pudo actualizar. Se reintentará en unos segundos.";
  }
  timer = setTimeout(refresh, REFRESH_MS);
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

if (loadToken()) refresh();
else showLogin("");
