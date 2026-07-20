(() => {
  const $ = (sel) => document.querySelector(sel);
  const alertFeed = $("#alert-feed");
  const alertBody = $("#alert-table tbody");
  const apBody = $("#ap-table tbody");
  const conn = $("#conn-status");

  let alertCount = 0;
  const frameHistory = {
    labels: [],
    beacon: [],
    deauth: [],
    eapol: [],
    probe_resp: [],
  };

  const chart = new Chart($("#frame-chart"), {
    type: "line",
    data: {
      labels: frameHistory.labels,
      datasets: [
        { label: "beacon", data: frameHistory.beacon, borderColor: "#3d8bfd", tension: 0.3 },
        { label: "deauth", data: frameHistory.deauth, borderColor: "#ff4d6d", tension: 0.3 },
        { label: "eapol", data: frameHistory.eapol, borderColor: "#f4c430", tension: 0.3 },
        { label: "probe_resp", data: frameHistory.probe_resp, borderColor: "#5cdb95", tension: 0.3 },
      ],
    },
    options: {
      responsive: true,
      plugins: { legend: { labels: { color: "#8b9bb8" } } },
      scales: {
        x: { ticks: { color: "#8b9bb8" }, grid: { color: "#1c273c" } },
        y: { ticks: { color: "#8b9bb8" }, grid: { color: "#1c273c" }, beginAtZero: true },
      },
    },
  });

  function fmtTime(ts) {
    if (!ts) return "—";
    return new Date(ts * 1000).toLocaleTimeString();
  }

  function fmtUptime(sec) {
    sec = Math.floor(sec || 0);
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  }

  function prependAlert(a) {
    alertCount += 1;
    $("#stat-alerts").textContent = String(alertCount);
    const div = document.createElement("div");
    div.className = `alert-item ${a.severity || "medium"}`;
    div.innerHTML = `
      <div class="meta">${fmtTime(a.timestamp)} · ${a.alert_type || ""}</div>
      <div class="title">${escapeHtml(a.title || "")}</div>
      <div class="evidence">${escapeHtml(a.evidence || "")}</div>`;
    alertFeed.prepend(div);
    while (alertFeed.children.length > 50) alertFeed.removeChild(alertFeed.lastChild);

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${fmtTime(a.timestamp)}</td>
      <td><span class="sev ${a.severity}">${a.severity}</span></td>
      <td>${escapeHtml(a.alert_type || "")}</td>
      <td>${escapeHtml(a.title || "")}</td>
      <td>${escapeHtml(a.evidence || "")}</td>`;
    alertBody.prepend(tr);
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function renderInventory(rows) {
    apBody.innerHTML = "";
    for (const ap of rows) {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(ap.ssid || "(hidden)")}</td>
        <td><code>${escapeHtml(ap.bssid || "")}</code></td>
        <td>${ap.channel ?? "—"}</td>
        <td>${escapeHtml(ap.encryption || "—")}</td>
        <td>${ap.rssi ?? "—"}</td>
        <td>${fmtTime(ap.last_seen)}</td>`;
      apBody.appendChild(tr);
    }
    $("#stat-aps").textContent = String(rows.length);
  }

  async function refreshStats() {
    try {
      const res = await fetch("/api/stats");
      const s = await res.json();
      $("#stat-frames").textContent = String(s.frames_total || 0);
      $("#stat-uptime").textContent = fmtUptime(s.uptime_seconds);
      $("#stat-aps").textContent = String(s.ap_count || 0);

      const fc = s.frame_counts || {};
      const label = new Date().toLocaleTimeString();
      frameHistory.labels.push(label);
      frameHistory.beacon.push(fc.beacon || 0);
      frameHistory.deauth.push(fc.deauth || 0);
      frameHistory.eapol.push(fc.eapol || 0);
      frameHistory.probe_resp.push(fc.probe_resp || 0);
      const maxPts = 30;
      for (const key of Object.keys(frameHistory)) {
        if (frameHistory[key].length > maxPts) frameHistory[key].shift();
      }
      chart.update();
    } catch (_) { /* ignore */ }
  }

  async function bootstrap() {
    try {
      const [alerts, inv] = await Promise.all([
        fetch("/api/alerts?limit=50").then((r) => r.json()),
        fetch("/api/inventory").then((r) => r.json()),
      ]);
      alertCount = 0;
      alertFeed.innerHTML = "";
      alertBody.innerHTML = "";
      for (const a of [...alerts].reverse()) prependAlert(a);
      renderInventory(inv);
    } catch (_) { /* ignore */ }
  }

  function connectSSE() {
    const es = new EventSource("/api/events/stream");
    es.onopen = () => {
      conn.textContent = "Live";
      conn.className = "status ok";
    };
    es.onerror = () => {
      conn.textContent = "Reconnecting…";
      conn.className = "status bad";
    };
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data);
        if (data.type === "hello") return;
        if (data.alert_type || data.title) prependAlert(data);
      } catch (_) { /* ignore */ }
    };
  }

  bootstrap();
  connectSSE();
  setInterval(refreshStats, 3000);
  setInterval(() => {
    fetch("/api/inventory").then((r) => r.json()).then(renderInventory).catch(() => {});
  }, 5000);
})();
