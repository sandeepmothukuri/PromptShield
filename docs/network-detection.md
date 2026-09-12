# Network Detection — Suricata and Zeek

This page states plainly what the network sensors do and do not see in this
lab. Both run, both produce logs, and **neither ships into the search index**, so
there are deliberately no dashboard panels or hunting queries for them.

## What is configured

| Sensor | Image | Capture | Rules / scripts | Log destination |
| --- | --- | --- | --- | --- |
| Suricata | `jasonish/suricata` | `-i eth0`, `network_mode: host` | `detections/suricata/promptshield.rules` (7 signatures) | `suricata_logs` volume, `/var/log/suricata/eve.json` |
| Zeek | `blacktop/zeek` | `-i eth0`, `network_mode: host` | `detections/zeek/llm_telemetry.zeek` | `zeek_logs` volume, `llm.log` |

## The limitation, stated directly

Both containers use `network_mode: host`. On a **Linux** host that means they
capture the host's `eth0`, which carries:

- browser or CLI traffic to the LLM-Monitor on `:8080` — **visible**
- Wazuh indexer and dashboard traffic on the host network — **visible**

It does **not** carry:

- `llm-monitor` → `ollama` on `:11434`, which stays on the `promptshield` bridge
  network and never reaches the host interface
- container-to-container traffic generally

On **macOS and Windows**, Docker Desktop runs containers inside a VM, so
`network_mode: host` does not expose the host's interfaces at all. The sensors
start but capture nothing useful. This is a Docker Desktop constraint, not a
configuration error in this repository.

A second consequence: the sensors are not attached to the `promptshield` network,
so they cannot see the leg that actually contains the prompt text after the
proxy has accepted it.

## What that means for the detections

| Asset | Status |
| --- | --- |
| `detections/suricata/promptshield.rules` | Syntactically valid and structurally checked in CI. Fires on clear-text HTTP to `:8080` when running on Linux. |
| `detections/zeek/llm_telemetry.zeek` | Loads and produces `llm.log`. Matches on the HTTP `Host` header against a configurable host set. |
| Suricata or Zeek alerts in OpenSearch | **Not implemented.** No shipper exists, so no index is populated. |
| Dashboard panels for `suricata-*` / `zeek-*` | **Deliberately absent.** `tests/test_dashboards.py` fails if they are added without a shipper. |

The earlier revision of this repository documented a "Suricata flows by SID"
panel and a "Zeek llm.log suspicious flag" panel against `suricata-*` and
`zeek-llm-*` indices. Neither index was ever written. Those panels were removed
rather than left to render empty.

## Making the sensors useful

Two supported options, depending on what you want to observe.

### Option A — observe client-to-proxy traffic (default)

Keep `network_mode: host`. Works on Linux. Covers inbound requests to `:8080`,
which is where an external attacker appears.

### Option B — observe proxy-to-model traffic

Attach the sensor to the compose network instead of the host:

```yaml
  suricata:
    image: jasonish/suricata:7.0.17
    network_mode: bridge          # was: host
    networks: [promptshield]
    cap_add: [NET_ADMIN, SYS_NICE]
    command: -i eth0 -S /etc/suricata/rules/promptshield.rules
```

Inside the bridge network the container's `eth0` carries the
`llm-monitor` → `ollama` leg, including the prompt in the request body. The
trade-off is that inbound client traffic is no longer visible.

### Option C — inline gateway

Run the proxy behind a reverse proxy or service mesh that terminates TLS and
forwards to Suricata/Zeek in inline mode. This is the production-realistic
deployment and is out of scope for the lab.

## Shipping the logs

If you want these alerts searchable, add a shipper. Filebeat is the smallest
option; point it at the log volume and the indexer:

```yaml
  filebeat-suricata:
    image: docker.elastic.co/beats/filebeat:8.13.4
    user: root
    networks: [promptshield]
    volumes:
      - suricata_logs:/var/log/suricata:ro
      - ./config/filebeat/suricata.yml:/usr/share/filebeat/filebeat.yml:ro
```

Then create the index pattern, and only then add a panel. The test that blocks
premature panels is
`tests/test_dashboards.py::test_no_panels_reference_data_sources_that_are_not_shipped`
— update it in the same commit as the shipper.

## Zeek specifics

`detections/zeek/llm_telemetry.zeek` declares a custom `Info` record and writes
`llm.log` with these fields:

| Field | Type | Notes |
| --- | --- | --- |
| `ts` | time | `network_time()` |
| `uid` | string | Zeek connection uid, joins to `conn.log` and `http.log` |
| `id_orig_h`, `id_resp_h` | addr | |
| `host` | string | HTTP `Host` header, without port |
| `uri` | string | unescaped request URI |
| `method` | string | |
| `status_code` | count | reply events only |
| `body_len` | count | request body length, request events only |
| `suspicious` | bool | true when an injection marker matched |
| `reason` | string | the marker that matched |

The host set and marker set are both `&redef`, so they can be extended from
`site/local.zeek` without editing the shipped script:

```zeek
redef PromptShield::llm_hosts += { "llm-gateway.internal" };
redef PromptShield::injection_markers += { "reveal your system prompt" };
```

The script reads the request body via `http_entity_data`, accumulates it per
connection, and writes the record on `http_message_done`. Markers are therefore
matched against the prompt, not just the URI. The earlier revision matched the
URI alone, which could never have fired against a POSTed JSON body — an LLM
prompt is never in the URL.

Accumulation is bounded by `max_body_bytes` (default 1 MiB, `&redef`). Bodies
larger than that are still logged with their true `body_len`, but only the first
`max_body_bytes` are searched, so a token flood cannot exhaust memory.

State is keyed by connection `uid` and deleted on `http_message_done`, with
`connection_state_remove` as a fallback for connections that close early.

Because the `zeek` binary is not available in CI, the script is checked
structurally by `tests/test_network_detections.py`: balanced braces, the
presence of a body handler that feeds the marker matcher, bounded accumulation,
per-connection cleanup, lowercase markers, port-tolerant host matching, and
agreement between the documented `Info` fields and the declared record.

## Verification

Zeek script load can be checked without traffic, but requires the Zeek binary,
which is not present in CI:

```bash
docker compose run --rm --entrypoint zeek zeek \
  -i eth0 /usr/local/zeek/share/zeek/site/llm_telemetry.zeek -e 'exit'
```

Suricata rule syntax likewise needs the binary:

```bash
docker compose run --rm --entrypoint suricata suricata \
  -T -S /etc/suricata/rules/promptshield.rules -l /tmp
```

What CI does check without the binaries is in
`tests/test_attack_mappings.py::test_suricata_rules_are_well_formed`: balanced
options, required keywords, unique SIDs, the documented SID range, and correct
flow directionality for request-body versus response-body matches.
