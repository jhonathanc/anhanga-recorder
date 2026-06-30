const state = {
  config: null,
  jobs: {},
  selected: new Set(),
  editingId: null,
  editingGroupId: null,
  editingCloudId: null,
  logs: [],
  previewSignature: "",
  previewRunId: 0,
  previewQueueActive: false,
};

const NEW_FORM = "__new__";
const PREVIEW_START_TIMEOUT_MS = 8000;
const PREVIEW_START_GAP_MS = 1200;
const DEFAULT_RTSP_PATH = "/cam/realmonitor?channel=1&subtype=0";

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || `HTTP ${response.status}`);
  }
  return data;
}

function fmtBytes(bytes) {
  if (!Number.isFinite(bytes)) return "-";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
}

function formatTime(value) {
  if (!value) return "-";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function makeLocalId(prefix) {
  return `${prefix}-${Math.random().toString(16).slice(2, 10)}`;
}

function t2uClouds() {
  return state.config?.t2uClouds || [];
}

function sourceGroups() {
  return state.config?.sourceGroups || [];
}

function cloudFor(id) {
  const needle = typeof id === "object" ? id?.t2uCloudId : id;
  return t2uClouds().find((cloud) => cloud.id === needle) || t2uClouds()[0] || null;
}

function groupFor(cameraOrId) {
  const groupId = typeof cameraOrId === "object" ? cameraOrId?.groupId : cameraOrId;
  const groupName = typeof cameraOrId === "object" ? cameraOrId?.group : "";
  const byId = sourceGroups().find((group) => group.id === groupId);
  if (byId) return byId;
  const lower = String(groupName || "").trim().toLowerCase();
  return lower ? sourceGroups().find((group) => group.name.trim().toLowerCase() === lower) || null : null;
}

function option(value, label, selected = false) {
  return `<option value="${escapeHtml(value)}" ${selected ? "selected" : ""}>${escapeHtml(label)}</option>`;
}

function sourceSubtitle(camera) {
  if (camera.type === "v4l2") {
    return [camera.videoDevice, camera.audioDevice].filter(Boolean).join(" + ");
  }
  if (camera.type === "cloud-p2p") {
    const group = groupFor(camera);
    const cloud = cloudFor(group || camera);
    const deviceId = group?.p2pUuid || camera.p2pUuid || "Sem ID P2P";
    const remoteIp = group?.p2pRemoteIp || camera.p2pRemoteIp || "127.0.0.1";
    const remotePort = group?.p2pRemotePort || camera.p2pRemotePort || 554;
    const groupName = group?.name || camera.group || "Sem grupo";
    return `${groupName} · ${deviceId} · ${remoteIp}:${remotePort} · ${cloud?.name || "Cloud"} · ${camera.rtspPath || ""}`;
  }
  return camera.url || "Sem URL";
}

function cameraGroupName(camera) {
  if (camera.type === "cloud-p2p") {
    return groupFor(camera)?.name || camera.group || "Sem grupo";
  }
  return camera.group || "";
}

function statusFor(camera) {
  const job = state.jobs[camera.id];
  if (!camera.enabled) return { text: "desativada", cls: "" };
  if (!job) return { text: "pronta", cls: "" };
  return { text: job.state || "ativa", cls: job.state || "" };
}

function renderSources() {
  const list = $("sourceList");
  const cameras = state.config?.cameras || [];
  if (!cameras.length) {
    list.innerHTML = `<div class="meta">Nenhuma fonte cadastrada.</div>`;
    return;
  }
  list.innerHTML = cameras.map((camera) => {
    const status = statusFor(camera);
    const checked = state.selected.has(camera.id) ? "checked" : "";
    const groupName = cameraGroupName(camera);
    const group = groupName ? `${groupName} · ` : "";
    const type = camera.type === "v4l2"
      ? "Linux"
      : camera.type === "cloud-p2p"
        ? "Cloud/P2P"
        : camera.stream === "extra" ? "Stream extra" : "Stream principal";
    return `
      <div class="source-row" data-id="${camera.id}">
        <input class="select-source" type="checkbox" ${checked} aria-label="Selecionar ${escapeHtml(camera.name)}">
        <div class="source-name">
          <strong>${escapeHtml(camera.name)}</strong>
          <span>${escapeHtml(sourceSubtitle(camera))}</span>
        </div>
        <span class="badge ${escapeHtml(status.cls)}">${escapeHtml(status.text)}</span>
        <span class="meta">${escapeHtml(group + type)}</span>
        <div class="row-actions">
          <button class="start-one">Gravar</button>
          <button class="stop-one">Parar</button>
          <button class="edit-one">Editar</button>
        </div>
      </div>
    `;
  }).join("");
}

function selectedCameras() {
  const cameras = state.config?.cameras || [];
  const ids = new Set(cameras.map((camera) => camera.id));
  state.selected = new Set(Array.from(state.selected).filter((id) => ids.has(id)));
  return cameras.filter((camera) => state.selected.has(camera.id));
}

function previewGroupFor(camera) {
  if (camera.type === "cloud-p2p") {
    const group = groupFor(camera);
    if (group) {
      return {
        key: `cloud:${group.id}`,
        limit: Number(group.maxSources || 0),
        name: group.name || "Grupo Cloud/P2P",
      };
    }
  }
  return { key: `source:${camera.id}`, limit: 0, name: "" };
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function waitForPreviewStart(img, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      img.removeEventListener("load", onLoad);
      img.removeEventListener("error", onError);
      resolve(result);
    };
    const onLoad = () => finish("load");
    const onError = () => finish("error");
    const timer = setTimeout(() => finish("timeout"), timeoutMs);
    img.addEventListener("load", onLoad, { once: true });
    img.addEventListener("error", onError, { once: true });
  });
}

function activePreviewCountForGroup(groupKey) {
  if (!groupKey) return 0;
  return Array.from(
    $("previewGrid").querySelectorAll('.preview-tile[data-preview-state="starting"], .preview-tile[data-preview-state="running"]')
  ).filter((tile) => tile.dataset.previewGroupKey === groupKey).length;
}

function previewTileCanStart(tile) {
  const limit = Number(tile.dataset.previewGroupLimit || 0);
  if (limit <= 0) return true;
  return activePreviewCountForGroup(tile.dataset.previewGroupKey) < limit;
}

function setPreviewQueuedStatus(tile) {
  const status = tile.querySelector(".preview-status");
  if (!status || tile.dataset.previewState !== "queued") return;
  const limit = Number(tile.dataset.previewGroupLimit || 0);
  if (limit > 0 && !previewTileCanStart(tile)) {
    status.textContent = "Limite do grupo";
  } else {
    status.textContent = "Aguardando vaga";
  }
}

function refreshQueuedPreviewStatuses() {
  Array.from($("previewGrid").querySelectorAll('.preview-tile[data-preview-state="queued"]'))
    .forEach(setPreviewQueuedStatus);
}

function enforcePreviewLimits() {
  const counts = new Map();
  const activeTiles = Array.from(
    $("previewGrid").querySelectorAll('.preview-tile[data-preview-state="starting"], .preview-tile[data-preview-state="running"]')
  ).sort((left, right) => Number(left.dataset.previewIndex || 0) - Number(right.dataset.previewIndex || 0));

  activeTiles.forEach((tile) => {
    const limit = Number(tile.dataset.previewGroupLimit || 0);
    if (limit <= 0) return;
    const key = tile.dataset.previewGroupKey;
    const count = counts.get(key) || 0;
    if (count >= limit) {
      stopPreviewTile(tile);
      tile.dataset.previewState = "queued";
      setPreviewQueuedStatus(tile);
      return;
    }
    counts.set(key, count + 1);
  });
}

function stopPreviewTile(tile) {
  const img = tile.querySelector("img");
  if (!img) return;
  img.removeAttribute("src");
  img.src = "";
}

function previewTileFor(cameraId) {
  return Array.from($("previewGrid").querySelectorAll(".preview-tile"))
    .find((tile) => tile.dataset.cameraId === cameraId);
}

function createPreviewTile(camera, src, index) {
  const previewGroup = previewGroupFor(camera);
  const tile = document.createElement("article");
  tile.className = "preview-tile";
  tile.dataset.cameraId = camera.id;
  tile.dataset.previewIndex = String(index);
  tile.dataset.previewState = "queued";
  tile.dataset.previewGroupKey = previewGroup.key;
  tile.dataset.previewGroupLimit = String(previewGroup.limit);
  tile.dataset.previewGroupName = previewGroup.name;
  tile.innerHTML = `
    <div class="preview-frame">
      <img data-src="${escapeHtml(src)}" alt="Preview ${escapeHtml(camera.name)}">
      <span class="preview-status">Aguardando vaga</span>
    </div>
    <div class="preview-title">
      <strong>${escapeHtml(camera.name)}</strong>
      <span>${escapeHtml(sourceSubtitle(camera))}</span>
    </div>
  `;
  return tile;
}

function updatePreviewTile(tile, camera, src, index) {
  const previewGroup = previewGroupFor(camera);
  tile.dataset.previewIndex = String(index);
  tile.dataset.previewGroupKey = previewGroup.key;
  tile.dataset.previewGroupLimit = String(previewGroup.limit);
  tile.dataset.previewGroupName = previewGroup.name;
  const title = tile.querySelector(".preview-title strong");
  const subtitle = tile.querySelector(".preview-title span");
  const img = tile.querySelector("img");
  const status = tile.querySelector(".preview-status");
  if (title) title.textContent = camera.name;
  if (subtitle) subtitle.textContent = sourceSubtitle(camera);
  if (img && img.dataset.src !== src) {
    stopPreviewTile(tile);
    img.dataset.src = src;
    tile.dataset.previewState = "queued";
    status.textContent = "Aguardando vaga";
  }
}

async function startPreviewQueue() {
  if (state.previewQueueActive) return;
  state.previewQueueActive = true;
  try {
    while (true) {
      refreshQueuedPreviewStatuses();
      const tile = Array.from($("previewGrid").querySelectorAll('.preview-tile[data-preview-state="queued"]'))
        .find(previewTileCanStart);
      if (!tile) break;

      if (!tile.isConnected) continue;
      const img = tile.querySelector("img");
      const status = tile.querySelector(".preview-status");
      if (!img?.dataset.src) continue;

      tile.dataset.previewState = "starting";
      status.textContent = "Iniciando";

      const started = waitForPreviewStart(img, PREVIEW_START_TIMEOUT_MS);
      img.src = img.dataset.src;
      const result = await started;
      if (!tile.isConnected) continue;

      if (result === "error") {
        tile.dataset.previewState = "error";
        status.textContent = "Erro";
      } else if (result === "timeout") {
        tile.dataset.previewState = "starting";
        status.textContent = "Carregando";
      } else {
        tile.dataset.previewState = "running";
        status.textContent = "Ao vivo";
      }

      refreshQueuedPreviewStatuses();
      const hasMoreQueuedWithCapacity = Array.from($("previewGrid").querySelectorAll('.preview-tile[data-preview-state="queued"]'))
        .some(previewTileCanStart);
      if (hasMoreQueuedWithCapacity) {
        await sleep(PREVIEW_START_GAP_MS);
      }
    }
  } finally {
    state.previewQueueActive = false;
    refreshQueuedPreviewStatuses();
    if (Array.from($("previewGrid").querySelectorAll('.preview-tile[data-preview-state="queued"]')).some(previewTileCanStart)) {
      startPreviewQueue();
    }
  }
}

function renderPreviews() {
  const section = $("previewSection");
  const grid = $("previewGrid");
  const cameras = selectedCameras();
  if (!cameras.length) {
    state.previewRunId += 1;
    Array.from(grid.querySelectorAll(".preview-tile")).forEach(stopPreviewTile);
    section.hidden = true;
    grid.innerHTML = "";
    state.previewSignature = "";
    return;
  }

  section.hidden = false;
  $("previewCount").textContent = `${cameras.length} selecionada${cameras.length === 1 ? "" : "s"}`;
  const selectedIds = new Set(cameras.map((camera) => camera.id));

  Array.from(grid.querySelectorAll(".preview-tile")).forEach((tile) => {
    if (!selectedIds.has(tile.dataset.cameraId)) {
      stopPreviewTile(tile);
      tile.remove();
    }
  });

  cameras.forEach((camera, index) => {
    const src = `/api/preview/${encodeURIComponent(camera.id)}.mjpg?rev=${encodeURIComponent(camera.updatedAt || "")}`;
    let tile = previewTileFor(camera.id);
    if (tile) {
      updatePreviewTile(tile, camera, src, index);
    } else {
      tile = createPreviewTile(camera, src, index);
    }
    grid.appendChild(tile);
  });

  state.previewSignature = cameras.map((camera) => `${camera.id}:${camera.updatedAt || ""}`).join("|");
  enforcePreviewLimits();
  refreshQueuedPreviewStatuses();
  startPreviewQueue();
}

function renderSettings() {
  const settings = state.config?.settings;
  if (!settings) return;
  $("outputDir").value = settings.outputDir || "";
  $("segmentSeconds").value = String(settings.segmentSeconds || 900);
  $("rtspTransport").value = settings.rtspTransport || "tcp";
  $("mapMode").value = settings.mapMode || "av";
  $("autoRestart").checked = Boolean(settings.autoRestart);
  $("alignSegmentsToClock").checked = Boolean(settings.alignSegmentsToClock);
  if (document.activeElement !== $("webUser")) {
    $("webUser").value = settings.webUser || "admin";
  }
  $("webPassword").placeholder = settings.webPasswordConfigured ? "Manter atual" : "";
}

function renderT2uCloudOptions() {
  const clouds = t2uClouds();
  const currentGroupCloudId = $("sourceGroupCloudId").value;
  const cloudOptions = clouds.map((cloud) => option(cloud.id, cloud.name, cloud.id === state.editingCloudId)).join("");
  $("t2uCloudSelect").innerHTML = option("", "Nova cloud", state.editingCloudId === NEW_FORM) + cloudOptions;
  $("sourceGroupCloudId").innerHTML = clouds.length
    ? clouds.map((cloud) => option(cloud.id, cloud.name, cloud.id === currentGroupCloudId)).join("")
    : option("", "Nenhuma cloud T2U");
}

function renderSourceGroupOptions() {
  const groups = sourceGroups();
  $("sourceGroupSelect").innerHTML =
    option("", "Novo grupo", state.editingGroupId === NEW_FORM) +
    groups.map((group) => option(group.id, group.name, group.id === state.editingGroupId)).join("");

  const currentValue = $("cloudGroupId").value;
  $("cloudGroupId").innerHTML =
    option("", "Selecione um grupo", !currentValue) +
    groups.map((group) => option(group.id, group.name, group.id === currentValue)).join("");
}

function renderConfigForms() {
  renderT2uCloudOptions();
  renderSourceGroupOptions();

  const clouds = t2uClouds();
  if (state.editingCloudId === null) {
    loadT2uCloudForm(clouds[0] || null);
  } else if (state.editingCloudId !== NEW_FORM && !clouds.some((cloud) => cloud.id === state.editingCloudId)) {
    loadT2uCloudForm(clouds[0] || null);
  } else {
    $("t2uCloudSelect").value = state.editingCloudId === NEW_FORM ? "" : state.editingCloudId;
  }

  const groups = sourceGroups();
  if (state.editingGroupId === null) {
    loadSourceGroupForm(groups[0] || null);
  } else if (state.editingGroupId !== NEW_FORM && !groups.some((group) => group.id === state.editingGroupId)) {
    loadSourceGroupForm(groups[0] || null);
  } else {
    $("sourceGroupSelect").value = state.editingGroupId === NEW_FORM ? "" : state.editingGroupId;
  }
}

function renderSystem(system) {
  const disk = system?.disk || {};
  const t2u = system?.t2u || {};
  const ffmpeg = system?.ffmpeg?.found ? "FFmpeg ok" : "FFmpeg nao encontrado";
  const t2uLine = t2u.loadable ? "T2U ok" : (t2u.message || "T2U indisponivel");
  const free = disk.free ? `${fmtBytes(disk.free)} livres` : "disco indisponivel";
  $("systemLine").textContent = `${ffmpeg} · ${t2uLine} · ${free} · ${disk.path || ""}`;
}

function renderLogs(logs) {
  state.logs = logs || state.logs;
  $("logBox").textContent = state.logs
    .map((line) => `${line.ts} ${line.level.padEnd(7)} ${line.sourceId || "server"} ${line.message}`)
    .join("\n");
}

async function refreshState() {
  const data = await api("/api/state");
  state.config = data.config;
  state.jobs = data.jobs || {};
  renderSystem(data.system);
  renderSettings();
  renderConfigForms();
  renderSources();
  renderPreviews();
  renderLogs(data.logs || []);
}

async function refreshRecordings() {
  const data = await api("/api/recordings");
  const rows = data.recordings || [];
  $("recordingsList").innerHTML = rows.length
    ? rows.map((file) => `
        <div class="recording-item">
          <span class="source-name"><strong>${escapeHtml(file.name)}</strong><span>${escapeHtml(file.relativePath)}</span></span>
          <span>${fmtBytes(file.size)}</span>
          <span>${formatTime(file.modified)}</span>
        </div>
      `).join("")
    : `<div class="meta">Nenhuma gravacao encontrada.</div>`;
}

function formCamera() {
  const type = $("type").value;
  return {
    id: $("sourceId").value || undefined,
    name: $("name").value.trim(),
    type,
    url: $("url").value.trim(),
    videoDevice: $("videoDevice").value.trim() || "/dev/video0",
    audioDevice: $("audioDevice").value.trim(),
    resolution: $("resolution").value.trim(),
    frameRate: $("frameRate").value.trim(),
    inputFormat: $("inputFormat").value.trim(),
    stream: $("stream").value,
    groupId: type === "cloud-p2p" ? $("cloudGroupId").value : "",
    rtspPath: $("rtspPath").value.trim() || DEFAULT_RTSP_PATH,
    group: type === "cloud-p2p" ? "" : $("group").value.trim(),
    enabled: $("enabled").checked,
  };
}

function loadForm(camera = null) {
  state.editingId = camera?.id || null;
  $("formTitle").textContent = camera ? "Editar fonte" : "Nova fonte";
  $("sourceId").value = camera?.id || "";
  $("name").value = camera?.name || "";
  $("type").value = camera?.type || "stream";
  $("url").value = camera?.url || "";
  $("videoDevice").value = camera?.videoDevice || "/dev/video0";
  $("audioDevice").value = camera?.audioDevice || "";
  $("resolution").value = camera?.resolution || "";
  $("frameRate").value = camera?.frameRate || "";
  $("inputFormat").value = camera?.inputFormat || "";
  $("stream").value = camera?.stream || "main";
  $("cloudGroupId").value = camera?.groupId || groupFor(camera)?.id || "";
  $("rtspPath").value = camera?.rtspPath || DEFAULT_RTSP_PATH;
  $("group").value = camera?.group || "";
  $("enabled").checked = camera?.enabled ?? true;
  $("deleteSource").hidden = !camera;
  syncTypeFields();
}

function syncTypeFields() {
  const isDevice = $("type").value === "v4l2";
  const isCloud = $("type").value === "cloud-p2p";
  $("streamFields").hidden = isDevice || isCloud;
  $("deviceFields").hidden = !isDevice;
  $("cloudFields").hidden = !isCloud;
  $("groupTagField").hidden = isCloud;
}

function formT2uCloud() {
  return {
    id: $("t2uCloudId").value || makeLocalId("cloud"),
    name: $("t2uCloudName").value.trim() || "T2U Cloud",
    t2uDllPath: $("t2uDllPath").value.trim(),
    t2uServer: $("t2uServer").value.trim(),
    t2uServerPort: Number($("t2uServerPort").value || 0),
    t2uServerKey: $("t2uServerKey").value,
    t2uDevicePassword: $("t2uDevicePassword").value,
    t2uConnectTimeoutSeconds: Number($("t2uConnectTimeoutSeconds").value || 30),
  };
}

function loadT2uCloudForm(cloud = null) {
  state.editingCloudId = cloud?.id || NEW_FORM;
  $("t2uCloudSelect").value = cloud?.id || "";
  $("t2uCloudId").value = cloud?.id || "";
  $("t2uCloudName").value = cloud?.name || "";
  $("t2uDllPath").value = cloud?.t2uDllPath || "../Libt2u Win32 SDK/libt2u.dll";
  $("t2uServer").value = cloud?.t2uServer || "";
  $("t2uServerPort").value = String(cloud?.t2uServerPort || 0);
  $("t2uServerKey").value = cloud?.t2uServerKey || "";
  $("t2uDevicePassword").value = cloud?.t2uDevicePassword || "";
  $("t2uConnectTimeoutSeconds").value = String(cloud?.t2uConnectTimeoutSeconds || 30);
  $("deleteT2uCloud").hidden = !cloud;
}

function formSourceGroup() {
  return {
    id: $("sourceGroupId").value || makeLocalId("group"),
    name: $("sourceGroupName").value.trim() || "Grupo Cloud/P2P",
    t2uCloudId: $("sourceGroupCloudId").value,
    maxSources: Number($("sourceGroupMaxSources").value || 0),
    p2pUuid: $("sourceGroupP2pUuid").value.trim(),
    p2pPassword: $("sourceGroupP2pPassword").value,
    p2pRemoteIp: $("sourceGroupP2pRemoteIp").value.trim() || "127.0.0.1",
    p2pRemotePort: Number($("sourceGroupP2pRemotePort").value || 554),
    p2pLocalPort: Number($("sourceGroupP2pLocalPort").value || 0),
    rtspUser: $("sourceGroupRtspUser").value.trim(),
    rtspPassword: $("sourceGroupRtspPassword").value,
    enabled: $("sourceGroupEnabled").checked,
  };
}

function loadSourceGroupForm(group = null) {
  state.editingGroupId = group?.id || NEW_FORM;
  $("sourceGroupSelect").value = group?.id || "";
  $("sourceGroupId").value = group?.id || "";
  $("sourceGroupName").value = group?.name || "";
  $("sourceGroupCloudId").value = group?.t2uCloudId || t2uClouds()[0]?.id || "";
  $("sourceGroupMaxSources").value = String(group?.maxSources || 0);
  $("sourceGroupP2pUuid").value = group?.p2pUuid || "";
  $("sourceGroupP2pPassword").value = group?.p2pPassword || "";
  $("sourceGroupP2pRemoteIp").value = group?.p2pRemoteIp || "127.0.0.1";
  $("sourceGroupP2pRemotePort").value = String(group?.p2pRemotePort || 554);
  $("sourceGroupP2pLocalPort").value = String(group?.p2pLocalPort || 0);
  $("sourceGroupRtspUser").value = group?.rtspUser || "";
  $("sourceGroupRtspPassword").value = group?.rtspPassword || "";
  $("sourceGroupEnabled").checked = group?.enabled ?? true;
  $("deleteSourceGroup").hidden = !group;
}

async function saveSource(event) {
  event.preventDefault();
  const camera = formCamera();
  if (state.editingId) {
    await api(`/api/cameras/${state.editingId}`, { method: "PUT", body: JSON.stringify(camera) });
  } else {
    await api("/api/cameras", { method: "POST", body: JSON.stringify(camera) });
  }
  loadForm();
  await refreshState();
}

async function deleteSource() {
  if (!state.editingId) return;
  await api(`/api/cameras/${state.editingId}`, { method: "DELETE" });
  state.selected.delete(state.editingId);
  loadForm();
  await refreshState();
  await refreshRecordings();
}

async function saveT2uCloud(event) {
  event.preventDefault();
  const cloud = formT2uCloud();
  const config = structuredClone(state.config);
  const index = (config.t2uClouds || []).findIndex((item) => item.id === cloud.id);
  cloud.updatedAt = new Date().toISOString();
  if (index >= 0) {
    cloud.createdAt = config.t2uClouds[index].createdAt;
    config.t2uClouds[index] = { ...config.t2uClouds[index], ...cloud };
  } else {
    cloud.createdAt = cloud.updatedAt;
    config.t2uClouds = [...(config.t2uClouds || []), cloud];
  }
  await api("/api/config", { method: "POST", body: JSON.stringify(config) });
  state.editingCloudId = cloud.id;
  await refreshState();
}

async function deleteT2uCloud() {
  const id = $("t2uCloudId").value;
  if (!id) return;
  if (sourceGroups().some((group) => group.t2uCloudId === id)) {
    alert("Cloud T2U em uso por grupo Cloud/P2P.");
    return;
  }
  if (t2uClouds().length <= 1) {
    alert("Mantenha pelo menos uma cloud T2U cadastrada.");
    return;
  }
  const config = structuredClone(state.config);
  config.t2uClouds = (config.t2uClouds || []).filter((cloud) => cloud.id !== id);
  await api("/api/config", { method: "POST", body: JSON.stringify(config) });
  state.editingCloudId = null;
  await refreshState();
}

async function saveSourceGroup(event) {
  event.preventDefault();
  const group = formSourceGroup();
  const config = structuredClone(state.config);
  const index = (config.sourceGroups || []).findIndex((item) => item.id === group.id);
  group.updatedAt = new Date().toISOString();
  if (index >= 0) {
    group.createdAt = config.sourceGroups[index].createdAt;
    config.sourceGroups[index] = { ...config.sourceGroups[index], ...group };
  } else {
    group.createdAt = group.updatedAt;
    config.sourceGroups = [...(config.sourceGroups || []), group];
  }
  await api("/api/config", { method: "POST", body: JSON.stringify(config) });
  state.editingGroupId = group.id;
  await refreshState();
}

async function deleteSourceGroup() {
  const id = $("sourceGroupId").value;
  if (!id) return;
  if ((state.config?.cameras || []).some((camera) => camera.groupId === id)) {
    alert("Grupo em uso por uma ou mais fontes.");
    return;
  }
  const config = structuredClone(state.config);
  config.sourceGroups = (config.sourceGroups || []).filter((group) => group.id !== id);
  await api("/api/config", { method: "POST", body: JSON.stringify(config) });
  state.editingGroupId = null;
  await refreshState();
}

async function saveSettings() {
  const config = structuredClone(state.config);
  const newPassword = $("webPassword").value;
  config.settings = {
    ...config.settings,
    outputDir: $("outputDir").value.trim(),
    segmentSeconds: Number($("segmentSeconds").value),
    rtspTransport: $("rtspTransport").value,
    mapMode: $("mapMode").value,
    autoRestart: $("autoRestart").checked,
    alignSegmentsToClock: $("alignSegmentsToClock").checked,
    webUser: $("webUser").value.trim() || "admin",
  };
  if (newPassword) {
    config.settings.webPassword = newPassword;
  }
  await api("/api/config", { method: "POST", body: JSON.stringify(config) });
  $("webPassword").value = "";
  await refreshState();
}

function recordingResultMessage(result) {
  const lines = [];
  const skipped = result?.skipped || [];
  const errors = result?.errors || [];
  const skippedByLimit = new Map();

  skipped.forEach((item) => {
    if (item.reason === "group_limit") {
      const key = `${item.groupId || item.groupName || "grupo"}:${item.limit || 0}`;
      if (!skippedByLimit.has(key)) {
        skippedByLimit.set(key, {
          groupName: item.groupName || item.groupId || "Grupo Cloud/P2P",
          limit: item.limit || 0,
          sources: [],
        });
      }
      skippedByLimit.get(key).sources.push(item.name || item.id || "Fonte");
    }
  });

  skippedByLimit.forEach((group) => {
    lines.push(
      `${group.groupName}: limite de ${group.limit} fonte(s) atingido. Ficaram de fora: ${group.sources.join(", ")}.`
    );
  });

  skipped.forEach((item) => {
    if (item.reason === "group_limit") return;
    if (item.reason === "already_running") {
      lines.push(`${item.name || item.id}: ja estava gravando.`);
    } else {
      lines.push(`${item.name || item.id}: ignorada (${item.reason || "sem motivo informado"}).`);
    }
  });

  errors.forEach((item) => {
    lines.push(`${item.name || item.id || "Fonte"}: ${item.message || "erro ao iniciar"}.`);
  });
  return lines.join("\n");
}

async function start(ids, all = false) {
  const result = await api("/api/record/start", { method: "POST", body: JSON.stringify({ ids, all }) });
  const message = recordingResultMessage(result);
  if (message) {
    alert(message);
  }
  await refreshState();
}

async function stop(ids, all = false) {
  await api("/api/record/stop", { method: "POST", body: JSON.stringify({ ids, all }) });
  await refreshState();
  await refreshRecordings();
}

async function probeCurrent() {
  const camera = formCamera();
  const result = await api("/api/probe", { method: "POST", body: JSON.stringify(camera) });
  $("probeResult").textContent = JSON.stringify(result, null, 2);
  $("probeDialog").showModal();
}

function selectedIds() {
  return Array.from(state.selected);
}

function buildRtspUrl() {
  const host = $("tplHost").value.trim();
  const port = $("tplPort").value.trim() || "554";
  const user = encodeURIComponent($("tplUser").value.trim());
  const pass = encodeURIComponent($("tplPass").value);
  const channel = $("tplChannel").value || "1";
  const subtype = $("tplSubtype").value;
  const auth = user ? `${user}${pass ? `:${pass}` : ""}@` : "";
  $("url").value = `rtsp://${auth}${host}:${port}/cam/realmonitor?channel=${channel}&subtype=${subtype}`;
  $("type").value = "stream";
  $("stream").value = subtype === "0" ? "main" : "extra";
  syncTypeFields();
}

function wireEvents() {
  $("sourceForm").addEventListener("submit", saveSource);
  $("type").addEventListener("change", syncTypeFields);
  $("newSource").addEventListener("click", () => loadForm());
  $("deleteSource").addEventListener("click", deleteSource);
  $("saveSettings").addEventListener("click", saveSettings);
  $("buildRtsp").addEventListener("click", buildRtspUrl);
  $("probeSource").addEventListener("click", probeCurrent);
  $("refreshRecordings").addEventListener("click", refreshRecordings);
  $("clearViewLog").addEventListener("click", () => $("logBox").textContent = "");
  $("startSelected").addEventListener("click", () => start(selectedIds()));
  $("startAll").addEventListener("click", () => start([], true));
  $("stopSelected").addEventListener("click", () => stop(selectedIds()));
  $("stopAll").addEventListener("click", () => stop([], true));
  $("t2uCloudForm").addEventListener("submit", saveT2uCloud);
  $("newT2uCloud").addEventListener("click", () => loadT2uCloudForm());
  $("deleteT2uCloud").addEventListener("click", deleteT2uCloud);
  $("t2uCloudSelect").addEventListener("change", (event) => {
    loadT2uCloudForm(t2uClouds().find((cloud) => cloud.id === event.target.value) || null);
  });
  $("sourceGroupForm").addEventListener("submit", saveSourceGroup);
  $("newSourceGroup").addEventListener("click", () => loadSourceGroupForm());
  $("deleteSourceGroup").addEventListener("click", deleteSourceGroup);
  $("sourceGroupSelect").addEventListener("change", (event) => {
    loadSourceGroupForm(sourceGroups().find((group) => group.id === event.target.value) || null);
  });

  $("sourceList").addEventListener("click", (event) => {
    const row = event.target.closest(".source-row");
    if (!row) return;
    const id = row.dataset.id;
    const camera = state.config.cameras.find((item) => item.id === id);
    if (event.target.classList.contains("select-source")) {
      event.target.checked ? state.selected.add(id) : state.selected.delete(id);
      renderPreviews();
      return;
    }
    if (event.target.classList.contains("edit-one")) loadForm(camera);
    if (event.target.classList.contains("start-one")) start([id]);
    if (event.target.classList.contains("stop-one")) stop([id]);
  });
}

async function boot() {
  wireEvents();
  loadForm();
  try {
    await refreshState();
    await refreshRecordings();
  } catch (error) {
    $("systemLine").textContent = error.message;
  }
  setInterval(() => refreshState().catch(() => {}), 2500);
  setInterval(() => refreshRecordings().catch(() => {}), 15000);
}

boot();
