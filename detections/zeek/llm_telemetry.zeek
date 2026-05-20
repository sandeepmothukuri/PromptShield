##! PromptShield-Lab — Zeek script that fingerprints LLM API traffic and
##! emits a structured llm.log alongside conn/http/dns/ssl.

module PromptShield;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ts:           time    &log;
        uid:          string  &log;
        id_orig_h:    addr    &log;
        id_resp_h:    addr    &log;
        host:         string  &log &optional;
        uri:          string  &log &optional;
        method:       string  &log &optional;
        status_code:  count   &log &optional;
        suspicious:   bool    &log &default=F;
        reason:       string  &log &optional;
    };
}

# LLM API hosts we monitor (extend via &redef in site/local.zeek).
const llm_hosts: set[string] = {
    "ollama",
    "openwebui",
    "llm-monitor",
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
} &redef;

# Injection / jailbreak markers, evaluated against the request URI and body.
const injection_markers: set[string] = {
    "ignore previous instructions",
    "disregard all prior",
    "override your system prompt",
    "dan mode",
    "you are now dan",
    "repeat the words above",
    "developer mode enabled",
} &redef;

event zeek_init() &priority=5
    {
    Log::create_stream(PromptShield::LOG, [$columns=Info, $path="llm"]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! c?$http ) return;

    local host = c$http?$host ? c$http$host : "";
    if ( host !in llm_hosts ) return;

    local matched: string = "";
    local hay = to_lower(unescaped_URI);
    for ( marker in injection_markers )
        {
        if ( marker in hay )
            {
            matched = marker;
            break;
            }
        }

    local info: Info = [
        $ts        = network_time(),
        $uid       = c$uid,
        $id_orig_h = c$id$orig_h,
        $id_resp_h = c$id$resp_h,
        $host      = host,
        $uri       = unescaped_URI,
        $method    = method,
        $suspicious = (matched != ""),
        $reason     = matched
    ];

    Log::write(PromptShield::LOG, info);
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( ! c?$http ) return;
    local host = c$http?$host ? c$http$host : "";
    if ( host !in llm_hosts ) return;

    local info: Info = [
        $ts          = network_time(),
        $uid         = c$uid,
        $id_orig_h   = c$id$orig_h,
        $id_resp_h   = c$id$resp_h,
        $host        = host,
        $status_code = code
    ];
    Log::write(PromptShield::LOG, info);
    }
