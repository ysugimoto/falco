# Function in simulator

The following table describes built-in functions that will return tentative values.
Will be updated when we find or implement a way to get accurate values.

| Function                                                                                              | Tentative Value/behavior                        |
|:-----------------------------------------------------------------------------------------------------:|:-----------------------------------------------:|
| *fastly.hash(key, seed, from, to)*                                                                    | Returns originally calculated hash string       |
| *h2.push(resource [, as])*                                                                            | Ignore variadic arguments of "as"               |
| *resp.tarpit(interval_s [, chunk_size_bytes])*                                                        | No effect due to not support tarpitting         |
| *early_hints(resource [, resources...])*                                                              | No effect due to not support h2 and h3          |
| *ratelimit.check_rate(entry, rc, delta, window, limit, pb, ttl)*                                      | Returns `false` due to no rate limiting support |
| *ratelimit.check_rates(entry, rc1, delta1, window1, limit1, rc2, delta2, windows2, limit2, pb, ttl)*  | Returns `false` due to no rate limiting support |
| *ratelimit.penaltybox_add(pb, entry, ttl)*                                                            | No effect due to no rate limiting support       |
| *ratelimit.penaltybox_has(pb, entry)*                                                                 | Returns `false` due to no rate limiting support |
| *ratelimit.ratecounter_increment(rc, entry, delta)*                                                   | Returns `0` due to no rate limiting support     |
