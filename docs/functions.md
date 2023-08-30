# Function in simulator

Following table describes built-in functions that will return tentative value.
Will be updated when we find or implement a way to get accurate values.

| Function                                     | Tentative Value / behavior               |
|:============================================:|:========================================:|
| fastly.hash(key, seed, from, to)             | returns originaly calculated hahs string |
| h2.push(resource [, as])                     | Ignore variadic arguments of "as"        |
| resp.tarpit(interval_s [, chunk_size_bytes]) | No effect due to not support tarpitting  |
