(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const els = {
    back: $("back"), forward: $("forward"), reload: $("reload"), home: $("home"),
    form: $("urlform"), url: $("url"), status: $("status"), report: $("report"),
    homepanel: $("homepanel"), errorpanel: $("errorpanel"), errorMsg: $("error-msg"),
    errorTitle: $("error-title"), errorUrl: $("error-url"), retry: $("error-retry"),
    loading: $("loading"), frame: $("frame"), recent: $("recent"), recentList: $("recent-list"),
    clearRecent: $("clear-recent"), modeRem: $("mode-rem"),
    filesBtn: $("files-btn"), files: $("files"), filesList: $("files-list"),
    filesMsg: $("files-msg"), filesRefresh: $("files-refresh"), filesClose: $("files-close"),
  };
  const RECENT_KEY = "safebrowse.recent";
  // Modo remoto: Chromium com tela (Selkies) em outra rota. Sem ele, o botão some.
  const SCREEN_URL = document.querySelector('meta[name="qp-remote-screen"]')?.content || "";
  // Ofuscação das URLs nos links do app (espelho de app/obfuscate.py). Não é criptografia.
  const obf = (() => {
    const KEY = new TextEncoder().encode("safebrowse-qp");
    const xor = (bytes) => bytes.map((b, i) => b ^ KEY[i % KEY.length]);
    const enc = (url) => {
      const bytes = xor(new TextEncoder().encode(url));
      let bin = ""; for (const b of bytes) bin += String.fromCharCode(b);
      return "~" + btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    };
    const dec = (token) => {
      token = (token || "").trim();
      if (!token.startsWith("~")) return token;
      try {
        const b64 = token.slice(1).replace(/-/g, "+").replace(/_/g, "/");
        const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
        const bytes = xor(Uint8Array.from(bin, (c) => c.charCodeAt(0)));
        return new TextDecoder().decode(bytes);
      } catch { return ""; }
    };
    return { enc, dec };
  })();
  let current = null;
  let requestSeq = 0;

  const LABELS = {
    removed_script: ["script", "removed"],
    removed_noscript: ["noscript", "removed"],
    removed_iframe: ["frame", "removed"],
    removed_object: ["object", "removed"],
    removed_embed: ["embed", "removed"],
    removed_meta: ["meta", "removed"],
    removed_link: ["link", "removed"],
    removed_base: ["base", "removed"],
    removed_template: ["template", "removed"],
    removed_math: ["mathml", "removed"],
    removed_handlers: ["handler on*", "removed"],
    removed_dangerous_attrs: ["atributo perigoso", "removed"],
    removed_resources: ["recurso", "removed"],
    forms_blocked: ["form POST bloqueado", "warn"],
    forms_rewritten: ["form GET", "proxied"],
    links_rewritten: ["link", "proxied"],
    resources_proxied: ["recurso", "proxied"],
    stylesheets_proxied: ["css", "proxied"],
    css_urls_rewritten: ["url() css", "proxied"],
    css_urls_dropped: ["url() css descartado", "removed"],
    css_dangerous: ["css perigoso", "removed"],
  };
  const HINTS = {
    challenge: "o site bloqueou o proxy com um desafio anti-bot (Cloudflare/Captcha)",
    needs_js: "esta página depende de JavaScript para mostrar conteúdo; sem scripts ela fica vazia",
  };

  // ---------- recentes ----------
  function loadRecent() {
    try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); } catch { return []; }
  }
  function saveRecent(list) {
    try { localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 30))); } catch {}
  }
  function pushRecent(url, title) {
    if (!url || url === "about:blank") return;
    const list = loadRecent().filter((e) => e.url !== url);
    list.unshift({ url, title: title || "", at: Date.now() });
    saveRecent(list);
  }
  function renderRecent() {
    const list = loadRecent();
    els.recent.hidden = list.length === 0;
    els.recentList.textContent = "";
    for (const entry of list) {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = appUrl(entry.url);
      a.textContent = entry.title ? entry.title : entry.url;
      if (entry.title) {
        const small = document.createElement("small");
        small.textContent = entry.url;
        a.appendChild(small);
      }
      li.appendChild(a);
      els.recentList.appendChild(li);
    }
  }

  // ---------- UI helpers ----------
  function show(panel) {
    els.homepanel.hidden = panel !== "home";
    els.errorpanel.hidden = panel !== "error";
    els.frame.hidden = panel !== "frame";
  }
  function setStatus(text, cls) {
    els.status.textContent = text || "";
    els.status.className = "status" + (cls ? " " + cls : "");
  }
  // O Chromium do modo com tela tem barra de endereço própria: a URL vai pela área de
  // transferência (o Selkies a repassa) e o usuário cola com Ctrl+L, Ctrl+V.
  function openScreen(url) {
    const go = () => { location.href = SCREEN_URL; };
    if (!url) { go(); return; }
    const copied = navigator.clipboard ? navigator.clipboard.writeText(url) : Promise.reject();
    copied.then(() => {
      setStatus("endereço copiado: no Remoto, Ctrl+L e Ctrl+V", "ok");
      setTimeout(go, 1200);
    }, go);
  }
  // ---------- arquivos baixados no Remoto ----------
  // O Chromium remoto salva em ~/Downloads e o Selkies serve essa pasta em
  // <SCREEN_URL>api/files/ (listagem HTML + arquivos com "attachment"; o portão
  // põe CSP sandbox + nosniff). A listagem é lida com DOMParser, que não roda
  // script, e nomes de arquivo (dado não confiável) só entram por textContent.
  const FILES_URL = SCREEN_URL ? SCREEN_URL.replace(/\/?$/, "/") + "api/files/" : "";
  const PARTIAL = /\.(crdownload|part|tmp)$/i;
  async function loadFiles() {
    els.filesList.textContent = "";
    els.filesMsg.hidden = false;
    els.filesMsg.textContent = "carregando…";
    let doc;
    try {
      const res = await fetch(FILES_URL, { credentials: "same-origin", cache: "no-store" });
      if (!res.ok) throw new Error(res.status === 403 ? "downloads desligados no Remoto" : "HTTP " + res.status);
      doc = new DOMParser().parseFromString(await res.text(), "text/html");
    } catch (err) {
      els.filesMsg.textContent = "não deu para listar: " + (err.message || err);
      return;
    }
    const entries = [];
    for (const row of doc.querySelectorAll("table#list tbody tr")) {
      const link = row.querySelector("a[href]");
      const cells = row.querySelectorAll("td");
      if (!link) continue;
      const href = link.getAttribute("href") || "";
      const name = link.textContent || "";
      // Só arquivos da raiz: nada de "../", subpastas, URL absoluta ou download pela metade.
      if (!href || href.includes("/") || href.includes(":") || href.startsWith("?") || PARTIAL.test(name)) continue;
      entries.push({ href, name, when: cells[1]?.textContent.trim() || "", size: cells[2]?.textContent.trim() || "" });
    }
    entries.sort((a, b) => b.when.localeCompare(a.when));
    if (!entries.length) {
      els.filesMsg.textContent = "nada baixado ainda. Baixe no Remoto e clique em atualizar.";
      return;
    }
    els.filesMsg.hidden = true;
    for (const e of entries) {
      const li = document.createElement("li");
      const a = document.createElement("a");
      a.href = FILES_URL + e.href;
      a.setAttribute("download", e.name);
      const name = document.createElement("span");
      name.className = "fname";
      name.textContent = e.name;
      const meta = document.createElement("small");
      meta.textContent = [e.size, e.when].filter(Boolean).join(" · ");
      a.append(name, meta);
      li.appendChild(a);
      els.filesList.appendChild(li);
    }
  }
  function toggleFiles(force) {
    const open = force ?? els.files.hidden;
    els.files.hidden = !open;
    els.filesBtn.setAttribute("aria-expanded", String(open));
    els.filesBtn.classList.toggle("active", open);
    if (open) loadFiles();
  }

  function appUrl(url) {
    return "/?u=" + obf.enc(url);
  }
  function humanBytes(n) {
    if (n < 1024) return n + " B";
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + " KB";
    return (n / 1024 / 1024).toFixed(2) + " MB";
  }
  function chip(text, cls) {
    const span = document.createElement("span");
    span.className = "chip " + cls;
    span.textContent = text;
    return span;
  }
  function renderReport(report, meta) {
    els.report.textContent = "";
    const chips = [];
    for (const h of meta.hints || []) {
      if (!HINTS[h]) continue;
      chips.push(chip("⚠ " + HINTS[h], "hint"));
    }
    if ((meta.hints || []).length && !meta.rendered) {
      const render = document.createElement("button");
      render.type = "button";
      render.className = "chip action";
      render.textContent = "⟳ renderizar com JS (continua isolado)";
      render.title = "O JavaScript roda na VPS; só o resultado, sem scripts, chega aqui";
      render.addEventListener("click", () => openIsolated(meta.url, { push: false, render: true }));
      chips.push(render);
    }
    if ((meta.hints || []).length && SCREEN_URL) {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "chip action";
      btn.textContent = "↗ abrir em modo remoto";
      btn.addEventListener("click", () => openScreen(meta.url));
      chips.push(btn);
    }
    if (meta.rendered) chips.push(chip("renderizado no servidor", "proxied"));
    chips.push(chip(`HTTP ${meta.status}`, meta.status < 400 ? "proxied" : "warn"));
    chips.push(chip(meta.content_type + " · " + humanBytes(meta.bytes), "proxied"));
    for (const [key, count] of Object.entries(report || {})) {
      if (!count) continue;
      const [label, cls] = LABELS[key] || [key, "warn"];
      chips.push(chip(`${count} ${label}`, cls));
    }
    for (const c of chips) els.report.appendChild(c);
    els.report.hidden = chips.length === 0;
  }
  function showError(err, url) {
    show("error");
    els.report.hidden = true;
    const titles = {
      blocked: "Bloqueado pelo guard",
      too_large: "Página grande demais",
      fetch_failed: "Falha ao buscar",
      unsupported_type: "Tipo de conteúdo não renderizado",
      rate_limited: "Muitas requisições",
      render_unavailable: "Renderização indisponível",
    };
    els.errorTitle.textContent = titles[err.code] || "Não foi possível abrir";
    els.errorMsg.textContent = err.message || String(err);
    els.errorUrl.textContent = url || "";
    document.title = "Erro — SafeBrowse";
    setStatus("erro", "bad");
  }

  // ---------- modo isolado ----------
  let pageAbort = null;
  let loadWatch = null;
  // Esconde o spinner quando o HTML do frame já está pronto para ler. O `onload` do
  // iframe só dispara depois de TODAS as imagens/CSS/fontes: um recurso lento
  // deixava o overlay por cima da página e a navegação parecia travada.
  function watchFrameReady(viewPath) {
    clearInterval(loadWatch);
    const done = () => { clearInterval(loadWatch); els.loading.hidden = true; };
    const started = Date.now();
    els.frame.onload = done;
    loadWatch = setInterval(() => {
      let doc = null;
      try { doc = els.frame.contentDocument; } catch {}
      const ready = doc && doc.location && doc.location.pathname === viewPath && doc.readyState !== "loading";
      if (ready || Date.now() - started > 8000) done();
    }, 100);
  }
  let lastRendered = false;
  async function openIsolated(url, { push = true, render = false } = {}) {
    const seq = ++requestSeq;
    // Navegação nova cancela a anterior (antes as duas continuavam rodando no servidor).
    if (pageAbort) pageAbort.abort();
    const ctrl = new AbortController();
    pageAbort = ctrl;
    const timer = setTimeout(() => ctrl.abort("timeout"), 45000);
    current = url;
    els.url.value = url;
    els.loading.hidden = false;
    setStatus("carregando…");
    if (push) history.pushState({ u: url }, "", appUrl(url));
    let data;
    try {
      const q = "/api/page?url=" + encodeURIComponent(obf.enc(url)) + (render ? "&render=1" : "");
      const resp = await fetch(q, { cache: "no-store", signal: ctrl.signal });
      data = await resp.json().catch(() => ({ error: "resposta inválida do servidor", code: "bad_json" }));
      if (!resp.ok) throw Object.assign(new Error(data.error || resp.statusText), { code: data.code, status: resp.status });
    } catch (err) {
      if (seq !== requestSeq) return;
      els.loading.hidden = true;
      if (ctrl.signal.aborted) err = { code: "fetch_failed", message: "o servidor demorou demais para responder; tente de novo" };
      showError(err, url);
      return;
    } finally {
      clearTimeout(timer);
      if (pageAbort === ctrl) pageAbort = null;
    }
    if (seq !== requestSeq) return;
    current = data.url;
    lastRendered = !!data.rendered;
    els.url.value = data.url;
    document.title = (data.title ? data.title + " — " : "") + "SafeBrowse";
    renderReport(data.report, data);
    pushRecent(data.url, data.title);
    const viewPath = "/view/" + encodeURIComponent(data.id);
    watchFrameReady(viewPath);
    els.frame.src = viewPath;
    show("frame");
    setStatus("isolado", "ok");
    updateNav();
  }

  // ---------- navegação comum ----------
  function open(url, opts = {}) {
    url = (url || "").trim();
    if (!url) { goHome(); return; }
    openIsolated(url, opts);
  }
  function goHome() {
    current = null;
    els.url.value = "";
    els.report.hidden = true;
    document.title = "SafeBrowse";
    setStatus("");
    renderRecent();
    show("home");
    els.frame.removeAttribute("src");
    updateNav();
  }
  function updateNav() {
    els.back.disabled = false;
    els.forward.disabled = false;
  }
  function fromLocation() {
    const params = new URLSearchParams(location.search);
    const u = obf.dec(params.get("u"));
    if (u) open(u, { push: false }); else goHome();
  }
  function reload() {
    if (!current) return;
    open(current, { push: false, render: lastRendered });
  }

  els.form.addEventListener("submit", (ev) => { ev.preventDefault(); open(els.url.value); });
  els.back.addEventListener("click", () => history.back());
  els.forward.addEventListener("click", () => history.forward());
  els.reload.addEventListener("click", reload);
  els.home.addEventListener("click", () => { history.pushState({}, "", "/"); goHome(); });
  els.retry.addEventListener("click", () => { if (current) open(current, { push: false }); });
  els.clearRecent.addEventListener("click", () => { saveRecent([]); renderRecent(); });
  els.modeRem.hidden = !SCREEN_URL;
  els.modeRem.addEventListener("click", () => openScreen(current));
  els.filesBtn.hidden = !FILES_URL;
  els.filesBtn.addEventListener("click", () => toggleFiles());
  els.filesRefresh.addEventListener("click", loadFiles);
  els.filesClose.addEventListener("click", () => toggleFiles(false));
  window.addEventListener("popstate", fromLocation);
  window.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape" && !els.files.hidden) toggleFiles(false);
    if (ev.key === "F5") { ev.preventDefault(); reload(); }
    if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === "l") { ev.preventDefault(); els.url.focus(); els.url.select(); }
    if (ev.altKey && ev.key === "ArrowLeft") { ev.preventDefault(); history.back(); }
    if (ev.altKey && ev.key === "ArrowRight") { ev.preventDefault(); history.forward(); }
  });

  fromLocation();
})();
