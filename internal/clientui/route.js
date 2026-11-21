const routeText = {
  "title": "\u0421\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 \u043c\u0430\u0440\u0448\u0440\u0443\u0442",
  "via": " \u2192 ",
  "on": "\u0412\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u043c\u0430\u0440\u0448\u0440\u0443\u0442",
  "turnOff": "\u0412\u044b\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u043c\u0430\u0440\u0448\u0440\u0443\u0442",
  "probe": "\u041f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0441\u0432\u044f\u0437\u044c",
  "off": "\u0412\u044b\u043a\u043b\u044e\u0447\u0435\u043d",
  "ready": "\u041f\u0440\u0430\u0432\u0438\u043b\u043e \u0432\u043a\u043b\u044e\u0447\u0435\u043d\u043e",
  "unknown": "\u0421\u0442\u0430\u0442\u0443\u0441 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u0435\u043d",
  "changing": "\u041f\u0440\u0438\u043c\u0435\u043d\u044f\u0435\u043c \u043d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438\u2026",
  "blocked": "\u0421\u0430\u0439\u0442 \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d \u00b7 \u0441\u043b\u0443\u0436\u0431\u0430 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430",
  "failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0432\u043a\u043b\u044e\u0447\u0438\u0442\u044c \u043c\u0430\u0440\u0448\u0440\u0443\u0442",
  "pending": "\u0421\u0432\u044f\u0437\u044c \u0435\u0449\u0451 \u043d\u0435 \u043f\u0440\u043e\u0432\u0435\u0440\u0435\u043d\u0430",
  "ok": "\u0421\u0432\u044f\u0437\u044c \u0447\u0435\u0440\u0435\u0437 \u0443\u0437\u0435\u043b \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0436\u0434\u0435\u043d\u0430",
  "no": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043e\u0442\u043a\u0440\u044b\u0442\u044c \u0441\u0430\u0439\u0442 \u0447\u0435\u0440\u0435\u0437 \u0443\u0437\u0435\u043b",
  "control_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0438\u0437\u043c\u0435\u043d\u0438\u0442\u044c \u0440\u0435\u0436\u0438\u043c. \u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u043a\u043b\u0438\u0435\u043d\u0442 \u0432 \u0430\u043a\u0442\u0438\u0432\u043d\u043e\u0439 \u043b\u043e\u043a\u0430\u043b\u044c\u043d\u043e\u0439 \u0441\u0435\u0441\u0441\u0438\u0438 Aspire.",
  "not_ready": "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u0435\u0449\u0451 \u043d\u0435 \u0433\u043e\u0442\u043e\u0432 \u043a \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0435.",
  "busy": "\u0414\u043e\u0436\u0434\u0438\u0442\u0435\u0441\u044c \u0437\u0430\u0432\u0435\u0440\u0448\u0435\u043d\u0438\u044f \u0442\u0435\u043a\u0443\u0449\u0435\u0433\u043e \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u044f.",
  "persists": "\u041f\u043e\u0441\u043b\u0435 \u0437\u0430\u043a\u0440\u044b\u0442\u0438\u044f \u043e\u043a\u043d\u0430 \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u043f\u0440\u043e\u0434\u043e\u043b\u0436\u0430\u0435\u0442 \u0440\u0430\u0431\u043e\u0442\u0430\u0442\u044c.",
  "invite": "\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u0435 \u0434\u043b\u044f \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0430",
  "domains": "\u0420\u0430\u0437\u0440\u0435\u0448\u0451\u043d\u043d\u044b\u0435 \u0441\u0430\u0439\u0442\u044b",
  "apply": "\u0412\u044b\u0431\u0440\u0430\u0442\u044c \u0441\u0430\u0439\u0442",
  "terms": "\u0423\u0441\u043b\u043e\u0432\u0438\u044f \u043e\u0442 \u0443\u0437\u043b\u0430",
  "day": "\u041e\u0441\u0442\u0430\u043b\u043e\u0441\u044c \u043d\u0430 \u0441\u0435\u0433\u043e\u0434\u043d\u044f",
  "month": "\u041e\u0441\u0442\u0430\u043b\u043e\u0441\u044c \u043d\u0430 \u043c\u0435\u0441\u044f\u0446",
  "speed": "\u041b\u0438\u043c\u0438\u0442 \u0441\u043a\u043e\u0440\u043e\u0441\u0442\u0438",
  "unlimited": "\u0431\u0435\u0437 \u043e\u0433\u0440\u0430\u043d\u0438\u0447\u0435\u043d\u0438\u044f",
  "kbps": " \u041a\u0411/\u0441",
  "no_domains": "\u0423 \u0443\u0437\u043b\u0430 \u043d\u0435\u0442 \u043e\u0442\u0434\u0435\u043b\u044c\u043d\u043e\u0433\u043e \u0441\u043f\u0438\u0441\u043a\u0430 \u0441\u0430\u0439\u0442\u043e\u0432 \u0434\u043b\u044f \u0432\u044b\u0431\u043e\u0440\u0430.",
  "invite_mismatch": "\u041f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u0435 \u043d\u0435 \u0434\u043b\u044f \u0443\u0441\u0442\u0430\u043d\u043e\u0432\u043b\u0435\u043d\u043d\u043e\u0433\u043e \u043d\u0430 Aspire \u0443\u0437\u043b\u0430, \u0448\u043b\u044e\u0437\u0430 \u0438\u043b\u0438 \u043a\u043b\u044e\u0447\u0430.",
  "policy_unavailable": "\u0423\u0437\u0435\u043b \u043d\u0435 \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u043b \u0443\u0441\u043b\u043e\u0432\u0438\u044f. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u0441\u0432\u044f\u0437\u044c \u0438 \u0432\u0435\u0440\u0441\u0438\u044e \u0443\u0437\u043b\u0430.",
  "domain_not_allowed": "\u0412\u043b\u0430\u0434\u0435\u043b\u0435\u0446 \u043d\u0435 \u0440\u0430\u0437\u0440\u0435\u0448\u0438\u043b \u044d\u0442\u043e\u0442 \u0441\u0430\u0439\u0442.",
  "stop_before_select": "\u0412\u044b\u043a\u043b\u044e\u0447\u0438\u0442\u0435 \u0441\u0438\u0441\u0442\u0435\u043c\u043d\u044b\u0439 \u043c\u0430\u0440\u0448\u0440\u0443\u0442 \u043f\u0435\u0440\u0435\u0434 \u0432\u044b\u0431\u043e\u0440\u043e\u043c \u0434\u0440\u0443\u0433\u043e\u0433\u043e \u0441\u0430\u0439\u0442\u0430.",
  "profile_failed": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0441\u043e\u0445\u0440\u0430\u043d\u0438\u0442\u044c \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0439 \u0441\u0430\u0439\u0442.",
  "invite_bad": "\u0424\u0430\u0439\u043b \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u044f \u043d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u0440\u043e\u0447\u0438\u0442\u0430\u0442\u044c.",
  "egress_mode": "\u0420\u0435\u0436\u0438\u043c \u0432\u044b\u0445\u043e\u0434\u0430",
  "egress_direct": "\u0422\u043e\u043b\u044c\u043a\u043e \u043f\u0440\u044f\u043c\u043e\u0439 \u0432\u044b\u0445\u043e\u0434",
  "egress_system": "\u041f\u043e \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0443 \u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440\u0430",
  "egress_physical": "\u0424\u0438\u0437\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441",
  "egress_tunnel": "\u0422\u0443\u043d\u043d\u0435\u043b\u044c / VPN",
  "egress_unknown": "\u041c\u0430\u0440\u0448\u0440\u0443\u0442 \u043d\u0435 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0451\u043d",
  "egress_blocked": "\u0417\u0430\u043f\u0440\u043e\u0441 \u0437\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d",
  "egress_failed": "\u041e\u0448\u0438\u0431\u043a\u0430 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f",
  "egress_connected": "\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0435 \u043e\u0442\u043a\u0440\u044b\u0442\u043e",
  "error": "\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0432\u044b\u043f\u043e\u043b\u043d\u0438\u0442\u044c \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0435."
};
const routeEndpoint = "/api/system-route";
const routeTokenKey = "exitnode-system-route";
const routeTokenFragment = location.hash.match(/^#exitnode-route=([a-f0-9]{64})$/);
if (routeTokenFragment) {
  sessionStorage.setItem(routeTokenKey, routeTokenFragment[1]);
  history.replaceState(null, "", location.pathname + location.search);
}
const routeToken = sessionStorage.getItem(routeTokenKey);
const routeHeaders = { "X-Exitnode-Route-Token": routeToken };
let routeState = null;
let routeBusy = false;

let shownPolicy = "";

function renderRoutePolicy(s) {
  $("routeInvite").textContent = routeText.invite;
  $("routeInvite").disabled = routeBusy;
  $("routeApply").textContent = routeText.apply;
  $("routeDomainLabel").textContent = routeText.domains;
  const terms = $("routeTerms");
  const picker = $("routeDomainPicker");
  const list = $("routeDomain");
  const policy = s.policy;
  terms.hidden = !policy;
  picker.hidden = !policy?.domains?.length;
  const egressNote = $("routeEgress");
  egressNote.hidden = !policy?.egress_mode;
  if (policy?.egress_mode) {
    const last = policy.last_egress;
    const mode = routeText["egress_" + policy.egress_mode] || routeText.egress_unknown;
    const summary = [routeText.egress_mode + " " + mode];
    if (last?.host === s.domain) {
      summary.push(routeText["egress_" + last.kind] || routeText.egress_unknown,
        routeText["egress_" + last.outcome], new Date(last.checked_at).toLocaleTimeString());
    }
    egressNote.textContent = summary.filter(Boolean).join(" · ");
  }
  if (!policy) return;

  const left = (cap, used) => cap ? fmt(Math.max(0, cap - used)) : routeText.unlimited;
  const checked = new Date(policy.checked_at).toLocaleTimeString();
  const speed = policy.rate_kbps ? policy.rate_kbps + routeText.kbps : routeText.unlimited;
  terms.textContent = [routeText.terms + " " + policy.owner + " (" + checked + ")",
    routeText.day + " " + left(policy.day_bytes, policy.day_used),
    routeText.month + " " + left(policy.month_bytes, policy.month_used),
    routeText.speed + " " + speed].join(" · ");
  if (!policy.domains?.length) terms.textContent += " " + routeText.no_domains;

  if (shownPolicy !== policy.checked_at) {
    const prev = list.value;
    list.replaceChildren(...policy.domains.map((domain) => {
      const option = document.createElement("option");
      option.value = option.textContent = domain;
      return option;
    }));
    if (policy.domains.includes(prev)) list.value = prev;
    else if (policy.domains.includes(s.domain)) list.value = s.domain;
    shownPolicy = policy.checked_at;
  }
  list.disabled = routeBusy || s.state !== "off";
  $("routeApply").disabled = list.disabled || !list.value || list.value === s.domain;
}

function renderRoute() {
  if (!routeState) return;
  const s = routeState;
  $("systemRouteCard").hidden = false;
  $("routeTitle").textContent = routeText.title;
  $("routePath").textContent = s.domain + routeText.via + s.owner;
  $("routeStatus").textContent = routeBusy ? routeText.changing : (routeText[s.state] || routeText.unknown);
  $("routeToggle").textContent = s.enabled ? routeText.turnOff : routeText.on;
  $("routeToggle").disabled = routeBusy || ["changing", "unknown"].includes(s.state);
  $("routeProbe").textContent = routeText.probe;
  $("routeProbe").disabled = routeBusy || s.state !== "ready";
  renderRoutePolicy(s);
  $("routePersistence").hidden = !s.enabled;
  $("routePersistence").textContent = routeText.persists;
  const result = $("routeResult");
  result.hidden = s.state !== "ready";
  result.textContent = s.checked_at
    ? routeText[s.probe === "ok" ? "ok" : "no"] + " (" + new Date(s.checked_at).toLocaleTimeString() + ")"
    : routeText.pending;
}

async function pollRoute() {
  try {
    const res = await fetch(routeEndpoint, { headers: routeHeaders, cache: "no-store" });
    if (!res.ok) return;
    routeState = await res.json();
  } catch (e) {
    if (routeState) routeState = { ...routeState, state: "unknown", probe: "", checked_at: "" };
  }
  renderRoute();
}

async function runRoute(action, fields = {}) {
  if (routeBusy) return;
  routeBusy = true;
  $("routeError").hidden = true;
  renderRoute();
  const res = await post(routeEndpoint, { action, ...fields }, routeHeaders);
  await pollRoute();
  routeBusy = false;
  renderRoute();
  if (res.error) {
    $("routeError").textContent = routeText[res.error] || routeText.error;
    $("routeError").hidden = false;
  }
}

if (routeToken) {
  $("routeToggle").addEventListener("click", () => runRoute(routeState.enabled ? "stop" : "start"));
  $("routeProbe").addEventListener("click", () => runRoute("probe"));
  $("routeInvite").addEventListener("click", () => $("routeInviteFile").click());
  $("routeDomain").addEventListener("change", renderRoute);
  $("routeApply").addEventListener("click", () => runRoute("select", { domain: $("routeDomain").value }));
  $("routeInviteFile").addEventListener("change", async () => {
    const file = $("routeInviteFile").files?.[0];
    $("routeInviteFile").value = "";
    if (!file) return;
    let invite;
    try {
      if (file.size > 4096) throw new Error();
      const {version, server, key} = JSON.parse(await file.text());
      invite = {version, server, key};
    } catch (_) {
      $("routeError").textContent = routeText.invite_bad;
      $("routeError").hidden = false;
      return;
    }
    await runRoute("invite", { invite });
  });
  pollRoute();
  setInterval(pollRoute, 1700);
}
