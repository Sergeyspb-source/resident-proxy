const ownerEgressText = {
  "heading": "\u0418\u0441\u0445\u043e\u0434\u044f\u0449\u0438\u0439 \u043c\u0430\u0440\u0448\u0440\u0443\u0442",
  "system": "\u041f\u043e \u043c\u0430\u0440\u0448\u0440\u0443\u0442\u0443 \u043a\u043e\u043c\u043f\u044c\u044e\u0442\u0435\u0440\u0430",
  "direct": "\u0422\u043e\u043b\u044c\u043a\u043e \u043f\u0440\u044f\u043c\u043e\u0439 \u0432\u044b\u0445\u043e\u0434",
  "physical": "\u0424\u0438\u0437\u0438\u0447\u0435\u0441\u043a\u0438\u0439 \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441",
  "tunnel": "\u0422\u0443\u043d\u043d\u0435\u043b\u044c / VPN",
  "unknown": "\u0418\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441 \u043d\u0435 \u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0451\u043d",
  "connected": "\u0421\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0435 \u043e\u0442\u043a\u0440\u044b\u0442\u043e",
  "blocked": "\u0417\u0430\u0431\u043b\u043e\u043a\u0438\u0440\u043e\u0432\u0430\u043d\u043e \u0440\u0435\u0436\u0438\u043c\u043e\u043c \u0432\u044b\u0445\u043e\u0434\u0430",
  "failed": "\u041e\u0448\u0438\u0431\u043a\u0430 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f",
  "pending": "\u041d\u043e\u0432\u044b\u0445 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u0439 \u043f\u043e\u043a\u0430 \u043d\u0435\u0442.",
  "apply": "\u041f\u0440\u0438\u043c\u0435\u043d\u0438\u0442\u044c",
  "offline": "\u041f\u0430\u043d\u0435\u043b\u044c \u0443\u0437\u043b\u0430 \u043d\u0435\u0434\u043e\u0441\u0442\u0443\u043f\u043d\u0430.",
  "note": "\u0418\u0437\u043c\u0435\u043d\u0435\u043d\u0438\u0435 \u0440\u0435\u0436\u0438\u043c\u0430 \u0437\u0430\u0432\u0435\u0440\u0448\u0438\u0442 \u0442\u0435\u043a\u0443\u0449\u0438\u0435 \u0441\u043e\u0435\u0434\u0438\u043d\u0435\u043d\u0438\u044f.",
  "unavailable": "\u041f\u0440\u043e\u0432\u0435\u0440\u043a\u0430 \u0438 \u043f\u0440\u0438\u0432\u044f\u0437\u043a\u0430 \u0444\u0438\u0437\u0438\u0447\u0435\u0441\u043a\u043e\u0433\u043e \u0438\u043d\u0442\u0435\u0440\u0444\u0435\u0439\u0441\u0430 \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b \u043d\u0430 Windows."
};
let ownerMode = "";
let egressBusy = false;
const egressSelect = $("egressMode");
const egressApply = $("egressApply");

$("egressTitle").textContent = ownerEgressText.heading;
egressSelect.options[0].textContent = ownerEgressText.system;
egressSelect.options[1].textContent = ownerEgressText.direct;
egressApply.textContent = ownerEgressText.apply;

function updateEgressButton() {
  egressApply.disabled = egressBusy || !ownerMode || egressSelect.value === ownerMode;
}

window.renderOwnerEgress = function (state) {
  const row = $("egressOverview");
  const card = $("egressSettings");
  if (!state?.egress_mode) {
    if (!card.hidden) $("egressLast").textContent = ownerEgressText.offline;
    ownerMode = "";
    egressSelect.disabled = true;
    updateEgressButton();
    row.hidden = true;
    return;
  }
  card.hidden = false;
  row.hidden = false;
  if (ownerMode !== state.egress_mode) {
    ownerMode = state.egress_mode;
    egressSelect.value = ownerMode;
  }
  egressSelect.disabled = egressBusy;
  egressSelect.options[1].disabled = !state.egress_supported;
  $("egressNote").textContent = state.egress_supported ? ownerEgressText.note : ownerEgressText.unavailable;
  updateEgressButton();

  const last = state.last_egress;
  const detail = last
    ? [last.host, ownerEgressText[last.kind] || ownerEgressText.unknown, last.interface,
       ownerEgressText[last.outcome], new Date(last.checked_at).toLocaleTimeString()].filter(Boolean).join(" · ")
    : ownerEgressText.pending;
  $("egressLast").textContent = detail;
  row.textContent = [ownerEgressText[ownerMode] || ownerEgressText.unknown, detail].join(" · ");
};

egressSelect.addEventListener("change", updateEgressButton);
egressApply.addEventListener("click", async () => {
  if (egressApply.disabled) return;
  egressBusy = true;
  egressSelect.disabled = true;
  updateEgressButton();
  try {
    const result = await post("/api/egress", { mode: egressSelect.value });
    if (result?.ok) await poll();
  } finally {
    egressBusy = false;
    egressSelect.disabled = !ownerMode;
    updateEgressButton();
  }
});
