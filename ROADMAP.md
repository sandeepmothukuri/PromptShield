# PromptShield-Lab Roadmap

A working document. Items under "Not started" are ideas, not commitments.

---

## Shipped

### v0.1 — Foundation

- [x] Docker Compose stack: Ollama, OpenWebUI, Wazuh, Suricata, Zeek, OpenSearch
- [x] LLM-Monitor proxy with a weighted multi-indicator classifier
- [x] Wazuh decoder plus rules 100100–100190 with ATT&CK tagging
- [x] Suricata signatures and Zeek `llm_telemetry.zeek`
- [x] OpenSearch Dashboards bundle
- [x] Threat-hunting query library
- [x] GitHub Actions CI

### v0.2 — Detection engineering (current)

- [x] 10 Sigma rules covering 10 attack types, validated with pySigma
- [x] Detection logic tested against the `datasets/` corpus rather than parsed only
- [x] Mappings verified against live ATT&CK v19.2 and ATLAS v5.6.0 feeds
- [x] Telemetry schema v2: 27 documented fields with a contract test
- [x] De-obfuscation for base64, ROT13 and hex payloads
- [x] Rate limiting and payload-size limits with documented thresholds
- [x] 7 attack simulations across 6 categories, including token flood and unsafe output
- [x] 5 SOC playbooks plus a post-incident template
- [x] 11 hunting queries with objective, triage, escalation and pivot
- [x] Dashboard regenerated from code, 12 panels, all against real fields
- [x] Documentation integrity enforced by test: no broken links, no unsupported claims

### Corrections made in v0.2

Recorded here because each one was a defect, not a feature.

- Removed `T1059.011` (Lua) as a catch-all for LLM execution. Prompt injection
  maps to `T1059`; obfuscated payloads map to `T1027`.
- Replaced `T1499.001` with `T1499.004` for application-layer exhaustion.
- Stopped mapping LLM secret disclosure to `T1041`/`T1567`. No network
  exfiltration is observed; `T1552` is what the evidence supports.
- Relabelled the `docs/img/` mockups as illustrative drawings and corrected the
  false facts they carried (Suricata 7.0.6 and "6 rules loaded" against a 7.0.17
  pin and 7 signatures; `T1041` and `T1566.001` against the audited mapping;
  invented repository star, fork, issue and pull-request counts). Each now
  carries a visible "not a captured screenshot" badge. `docs/screenshots.md`
  separates diagrams, mockups and real captures.
- Removed dashboard panels targeting `suricata-*` and `zeek-llm-*`, which
  nothing ever populated.
- Removed claims of a Sigma-to-Wazuh CI converter that does not exist.
- Corrected `sigma convert -t opensearch` in CI, which is not a valid backend
  and made that workflow fail.
- Pinned lint and Sigma tooling. Unpinned `pip install ruff` was failing as
  ruff's default rule set expanded.
- Extended CI to run `tests/` as well as `llm-monitor/tests/`. The main
  detection suites were never running in CI.
- Wired OpenWebUI through the monitor. It was configured with
  `OLLAMA_BASE_URL=http://ollama:11434`, so every chat request from the UI
  bypassed classification, blocking and telemetry; the monitor only ever saw the
  simulation scripts. It now uses `OPENAI_API_BASE_URL=http://llm-monitor:8080/v1`
  with `ENABLE_OLLAMA_API=false`, and the proxy gained `GET /v1/models`, without
  which the front-end model picker is empty.
- Audited upstream failures. An allowed prompt whose model call failed raised
  before `_audit` ran, so a model outage or a DoS against the runtime produced no
  telemetry at all. Both endpoints now record the failure with
  `response_status` and `detection_reason=upstream_failure:<code>`.
- Fixed request-id correlation on the error path. The 503 body returned
  `request_id: "unknown"` while the audit line carried the real id, so a failed
  request could not be tied to its record during triage.
- Corrected `FLAG_THRESHOLD`, which was `0.30` in `.env.example` and `0.65` in
  `docker-compose.yml`. Anyone who did not copy `.env.example` got the value the
  score-distribution analysis had rejected.

---

## Not started

### Detection depth

- [ ] Retrieved-content boundary marker. Once an injected instruction is
      inlined into a prompt by a browsing or RAG agent, the text is
      indistinguishable from a directly pasted one, so
      `simulations/prompt_injection/indirect_injection.py` stage 2 is
      classified as `prompt_injection` (T1059) rather than
      `indirect_prompt_injection` (T1566.002). Fixing this needs the calling
      application to tag retrieved text as a separate request field, which is a
      schema change.
- [ ] Tool-call and function-calling telemetry. This is the gap behind
      LLM06 (Excessive Agency); `excessive_agency_tool_abuse` is designed but
      cannot be implemented without a `tool` field in the schema.
- [ ] Model supply-chain detections (`model_supply_chain_pull`, T1195.002).
      Requires registry telemetry the proxy does not see.
- [ ] DNS-based exfiltration correlation. `data_exfiltration_dns_via_llm`
      (T1048.003) needs Zeek DNS logs indexed, which they are not.
- [ ] Vector and embedding store coverage (LLM08). No RAG component in the lab.
- [ ] Retrieval-poisoning simulation (LLM04).
- [ ] An LLM-as-judge red-team agent that iteratively probes the proxy.

### Pipeline

- [ ] Ship Suricata `eve.json` and Zeek `llm.log` to the indexer, then add the
      panels. The test blocking premature panels must be updated in the same
      commit.
- [ ] Attach the sensors to the compose network so they can see the
      proxy-to-model leg, or document inline deployment.
- [ ] Replace the demo Wazuh credentials and move them out of `.env.example`.
- [ ] Add compose healthchecks, `depends_on` conditions and image digests.
- [ ] Run containers as non-root.

### Response

- [ ] Implement `POST /admin/block_session` on the proxy, with authentication.
      `playbooks/prompt_injection_response.md` previously told analysts to call
      it; that instruction was removed because the endpoint does not exist. It
      must not be added without auth — anyone able to reach `:8080` could
      otherwise deny service to arbitrary users.
- [ ] SOAR integration example with an analyst-in-the-loop gate.
- [ ] Alert routing with severity-based escalation.

### Deployment

- [ ] Kubernetes manifests.
- [ ] Multi-tenant proxy with per-tenant policy and budgets.
- [ ] OpenTelemetry traces spanning prompt to completion.

---

## Ideas

- Browser-agent prompt-injection scenarios
- MCP-server abuse detections
- Vector-DB exfiltration scenarios
- Watermark-stripping detection
- Cross-model evasion: the same payload paraphrased per model

Open a Discussion with the **idea** label rather than a PR for anything here.
