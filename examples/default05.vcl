# Configuration for Fastly's Edge Rate Limiter
#
# This is intended to be a course-grained bot mitigation. More information
# here: https://docs.google.com/document/d/11jaryp4k_0c4LWWm7nQqHtoy9DvDGhCtOEzn1_okXgg/edit#
#
# Current state: deployed in limited PoPs
#

table erl_rollout {}

penaltybox ip_pbox {}
ratecounter ip_counter_10s {}
ratecounter ip_counter_60s {}

ratecounter auth_counter_60s {}
penaltybox auth_fingerprint_pbox {}

penaltybox tls_fingerprint_pbox {}
ratecounter tls_fingerprint_counter_10s {}
ratecounter tls_fingerprint_counter_60s {}

# sub edge_rate_limit_enabled BOOL {
#   declare local var.erl_rollout_permille INTEGER;
#   set var.erl_rollout_permille = std.atoi(table.lookup(erl_rollout, "erl_rollout_permille", "0"));
#   return randombool(var.erl_rollout_permille, 1000);
# }

# sub edge_rate_limit_enabled_loggedin BOOL {
#   declare local var.erl_rollout_permille_loggedin INTEGER;
#   set var.erl_rollout_permille_loggedin = std.atoi(table.lookup(erl_rollout, "erl_rollout_permille_loggedin", "0"));

#   return randombool(var.erl_rollout_permille_loggedin, 1000);
# }

# sub edge_rate_limit_enabled_loggedout BOOL {
#   declare local var.erl_rollout_permille_loggedout INTEGER;
#   set var.erl_rollout_permille_loggedout = std.atoi(table.lookup(erl_rollout, "erl_rollout_permille_loggedout", "0"));
#   return randombool(var.erl_rollout_permille_loggedout, 1000);
# }

acl erl_higher_limit_ips {
// IP range, format:
// (we will be reviewing and removing them as needed)
// # Context on why this IP deems a higher limit
  #AgotoZ HK Limited is a low fraud risk ISP
  "154.89.5.161"/32;
  # Vodafone Portugal
  "94.62.162.156"/32;
}

table erl_higher_limit_tls_sig {
// TLS Signature, format "key" : "jira ticket"
// (we will be reviewing and removing them as needed)
// # Context on why this TLS signature deems a higher limit
// "IVHBdSQP4TqgFmYBzm/RkMJ30cY=2En0Dm+2FTmifonrr93hM5awiYg=": "Mesh-xxx",
}

table erl_allowlist_account_id {
// Account id, format "key" : "jira ticket"
// key is req.http.Cookie:reddit_session + digest.hash_sha256(req.http.Authorization)
// digest.hash_sha256(req.http.Authorization) == req.http.Authorization.hash in Fastly ELK logs
// (we will be reviewing and removing them as needed)
// # Context on why this IP signature is allowed explictly
// "4242424242024b5d5fe84e982225661802471d4a316d9a7b299b1a565e588295ab4c41fde00c": "Mesh-xxx",
}

sub edge_rate_limit_run {
  if (req.http.X-Reddit-ERL-Block == "1") {
    error 739 "Manual ERL triggered";
  }

  # When you acquire a token, the Auth Bearer value is the client_id:secret
  # of the OAuth2 app which will be the same for all users using that app.
  # Which means that the ERL is not effective as the key is shared between
  # multiple clients.
  # https://github.com/reddit-archive/reddit/wiki/OAuth2#retrieving-the-access-token
  if ( (std.strlen(req.http.Cookie:reddit_session) > 0 || std.strlen(req.http.Authorization) > 0)
         && req.url !~ "api/v1/access_token"
         && req.url !~ "api/v1/refresh_token") {

    if (req.http.User-Agent ~ "(?i)Relay by /u/DBrady") {
      return;
    }

    declare local var.auth_combined_key STRING;
    # The key selection might seem a bit odd at first but there is a reason for it.
    # On why we hash the req.http.Authorization
    # We could use the req.http.Authorization as part of key however this is problematic for allowlists
    # Since we avoid storing secrets on Fastly logs we instead store digest.hash_sha256(req.http.Authorization)
    # which means that if we can explictly allowlist a user based on the data that we have at logs
    # On why we hash the key again
    # We use the extra hash to make sure that the key is fized size
    # regardless of long the underlying keys become thus futureproofing ourselves
    # The key meets the requirements set by fastly
    # key length is 256 bits -> 32 bytes < 256 bytes long.
    set var.auth_combined_key = req.http.Cookie:reddit_session + digest.hash_sha256(req.http.Authorization);
    // Skip if explicitly allowed
    if (edge_rate_limit_enabled_loggedin() && table.lookup(erl_allowlist_account_id, var.auth_combined_key, "0") == "0") {
      declare local var.ratelimit_exceeded BOOL;
      set var.ratelimit_exceeded = ratelimit.check_rate(
        digest.hash_sha256(var.auth_combined_key),
        auth_counter_60s,
        1,      # Increment.
        60,     # Sample window (seconds)
        135,
        auth_fingerprint_pbox,
        2m);

      # TODO(sean.rees): change these to variables instead -- we do this exclusively for
      # logging and don't need it to ride in the request
      set req.http.X-Reddit-ERL:auth_exceeded = if(var.ratelimit_exceeded, "true", "false");
      set req.http.X-Reddit-ERL:auth_bucket_10s = std.itoa(ratecounter.auth_counter_60s.bucket.10s);
      set req.http.X-Reddit-ERL:auth_bucket_60s = std.itoa(ratecounter.auth_counter_60s.bucket.60s);
    }
  } else {
    declare local var.tls_combined_sig STRING;
    declare local var.ip_and_tls_sig STRING;
    declare local var.ip_ratelimit_exceeded BOOL;
    declare local var.tls_ratelimit_exceeded BOOL;

    # Length: 56 chars.
    set var.tls_combined_sig = tls.client.ciphers_sha + tls.client.tlsexts_sha;

    # Max length 95 chars (56 chars + 39 is maximum length for IPv6 addr)
    # 95 << 256 byte limit.
    set var.ip_and_tls_sig = var.tls_combined_sig + std.ip2str(client.ip);

    // Skip if explicitly allowed
    if (edge_rate_limit_enabled_loggedout()) {
      # For the tls_ip rate limiter we consider two types of limits:
      # Short window limit over a 10s period
      # Long window limit over a 60s period
      # the limits are tuned based on historical data
      # we increment both at the same time with a single invocation to check_rates
      # The limits are set based on the following calculations:
      # limit_window_s = ceil(limit / window * error_margin_per_window * safety_factor)
      # limit: selected from the data
      # window: 10s or 60s
      # error margin per window:
      # https://docs.fastly.com/en/guides/working-with-rate-limiting-policies#limitations-and-caveats
      #       (+/-) ~50% for the 1 second time window
      #       (+/-) ~25% for the 10 second time window
      #       (+/-) ~10% for the 60 second time window
      # safety_factor: 110%
      declare local var.rps_short_window_limit INTEGER;
      set var.rps_short_window_limit = 115;
      declare local var.rps_long_window_limit INTEGER;
      set var.rps_long_window_limit = 101;

      # Some IPs are shared by ISPs/institutions etc so
      # they should have a higher limit
      if (client.ip !~ erl_higher_limit_ips &&
         table.lookup(erl_higher_limit_tls_sig, var.tls_combined_sig, "0") == "0") {
           set var.rps_short_window_limit *= 3;
           set var.rps_long_window_limit *= 3;
      }

      set var.ip_ratelimit_exceeded = ratelimit.check_rates(
        var.ip_and_tls_sig, # key
        ip_counter_10s, # rate counter short window
        1,      # Increment.
        10,     # Sample window short (seconds)
        var.rps_short_window_limit,    # Limit in RPS for short window
        ip_counter_60s, # rate counter long window
        1,      # Increment.
        60,     # Sample window long (seconds)
        var.rps_long_window_limit,   # Limit in RPS for long window
        ip_pbox,
        2m);


      set var.tls_ratelimit_exceeded = ratelimit.check_rates(
        var.tls_combined_sig,
        tls_fingerprint_counter_10s,
        1,      # Increment.
        10,     # Sample window (short, in seconds)
        100,    # Limit in RPS for the short window
        tls_fingerprint_counter_60s,
        1,      # Increment
        60,     # Sample window (long, in seconds)
        500,    # Limit in RPS for long window
        tls_fingerprint_pbox,
        2m);

      set req.http.X-Reddit-ERL:tls_exceeded = if(var.tls_ratelimit_exceeded, "true", "false");
      set req.http.X-Reddit-ERL:tls_bucket_10s = std.itoa(ratecounter.tls_fingerprint_counter_10s.bucket.10s);
      set req.http.X-Reddit-ERL:tls_bucket_60s = std.itoa(ratecounter.tls_fingerprint_counter_60s.bucket.60s);

      # Per: https://developer.fastly.com/reference/vcl/variables/client-request/req-http/
      # values in req.http are strings -- this is the reason we cast to str.
      #
      # TODO(sean.rees): change these to variables instead -- we do this exclusively for
      # logging and don't need it to ride in the request.
      set req.http.X-Reddit-ERL:ip_exceeded = if(var.ip_ratelimit_exceeded, "true", "false");
      set req.http.X-Reddit-ERL:ip_bucket_10s = std.itoa(ratecounter.ip_counter_10s.bucket.10s);
      set req.http.X-Reddit-ERL:ip_bucket_60s = std.itoa(ratecounter.ip_counter_60s.bucket.60s);

      # We controll the rollout per PoP with a fastly dictionary to revert more easily
      declare local var.erl_rollout_dictionary_key STRING;
      set var.erl_rollout_dictionary_key = "erl_rollout_permille_" + server.datacenter;

      if (randombool(std.atoi(table.lookup(erl_rollout, "erl_rollout_permille_worldwide",  "0")), 1000)
          || randombool(std.atoi(table.lookup(erl_rollout, var.erl_rollout_dictionary_key,  "0")), 1000)) {
        if (var.ip_ratelimit_exceeded) {
          error 739 "IP ERL exceeded";
        }
      }
    }
  }

  set req.http.X-Reddit-ERL:sampled = "true";
}
