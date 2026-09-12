##! PromptShield-Lab — Zeek script that fingerprints LLM API traffic and
##! emits a structured llm.log alongside conn/http/dns/ssl.
##!
##! Markers are evaluated against the request URI *and* the reassembled request
##! body, because an LLM prompt is sent as a JSON POST body and never appears in
##! the URI. Matching the URI alone would never fire against this traffic.

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
        body_len:     count   &log &default=0;
        suspicious:   bool    &log &default=F;
        reason:       string  &log &optional;
    };

    ## LLM API hosts we monitor (extend via &redef in site/local.zeek).
    ## Matched against the HTTP Host header with any port stripped.
    global llm_hosts: set[string] = {
        "ollama",
        "openwebui",
        "llm-monitor",
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
    } &redef;

    ## Injection / jailbreak markers, evaluated against the request URI and the
    ## reassembled request body (extend via &redef in site/local.zeek).
    global injection_markers: set[string] = {
        "ignore previous instructions",
        "disregard all prior",
        "override your system prompt",
        "dan mode",
        "you are now dan",
        "repeat the words above",
        "developer mode enabled",
    } &redef;

    ## Upper bound on body bytes retained for matching. Prompts larger than this
    ## are still logged with their true length, but only the first
    ## max_body_bytes are searched, which keeps memory bounded under a token
    ## flood. 1 MiB is far above a normal prompt and well below an abusive one.
    global max_body_bytes: count = 1048576 &redef;
}

# Per-connection accumulation state. Keyed by connection uid so concurrent
# requests on different connections do not interleave.
type State: record {
    host:    string;
    method:  string;
    uri:     string;
    body:    string;
    matched: string;
};

global states: table[string] of State;

# Strip an optional ":port" so "llm-monitor:8080" still matches "llm-monitor".
function strip_port(h: string): string
    {
    local idx = find_last(h, ":");
    if ( idx == 0 )
        return h;
    # IPv6 literals contain colons but are bracketed; only strip when what
    # follows the last colon is entirely digits.
    local tail = sub_bytes(h, idx + 1, |h|);
    if ( tail == "" || ! is_digit(tail[0]) )
        return h;
    for ( i in tail )
        if ( ! is_digit(tail[i]) )
            return h;
    return sub_bytes(h, 1, idx - 1);
    }

# Return the marker found in `hay`, or "" if none.
function match_markers(hay: string): string
    {
    local low = to_lower(hay);
    for ( marker in injection_markers )
        if ( marker in low )
            return marker;
    return "";
    }

event zeek_init() &priority=5
    {
    Log::create_stream(PromptShield::LOG, [$columns=Info, $path="llm"]);
    }

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string)
    {
    if ( ! c?$http )
        return;

    local host = c$http?$host ? strip_port(c$http$host) : "";
    if ( host !in llm_hosts )
        return;

    # Do not log yet: the body has not arrived. Logging here is what made the
    # original version blind to POSTed prompts.
    states[c$uid] = State($host=host, $method=method, $uri=unescaped_URI,
                          $body="", $matched=match_markers(unescaped_URI));
    }

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
    {
    if ( ! is_orig )
        return;
    if ( c$uid !in states )
        return;

    local st = states[c$uid];
    if ( |st$body| < max_body_bytes )
        st$body += data;

    if ( st$matched == "" )
        st$matched = match_markers(st$body);
    }

event http_message_done(c: connection)
    {
    if ( c$uid !in states )
        return;

    local st = states[c$uid];

    Log::write(PromptShield::LOG, Info(
        $ts         = network_time(),
        $uid        = c$uid,
        $id_orig_h  = c$id$orig_h,
        $id_resp_h  = c$id$resp_h,
        $host       = st$host,
        $uri        = st$uri,
        $method     = st$method,
        $body_len   = |st$body|,
        $suspicious = (st$matched != ""),
        $reason     = st$matched
    ));

    delete states[c$uid];
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( ! c?$http )
        return;
    local host = c$http?$host ? strip_port(c$http$host) : "";
    if ( host !in llm_hosts )
        return;

    Log::write(PromptShield::LOG, Info(
        $ts          = network_time(),
        $uid         = c$uid,
        $id_orig_h   = c$id$orig_h,
        $id_resp_h   = c$id$resp_h,
        $host        = host,
        $status_code = code
    ));
    }

event connection_state_remove(c: connection)
    {
    # Guard against a connection closing without http_message_done.
    if ( c$uid in states )
        delete states[c$uid];
    }
