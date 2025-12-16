# Variables in simulator

Following table describes variables that will return tentative values,
but you can override these values by configuration or cli arguments for testing.

## Overide by Configuration

Put override configuration in `testing.overrides` section as map.

```yaml
...
testing:
    overrides:
      client.class.checker: true
      client.as.name: "overridden"
...
```

## CLI

Provide `-o, --override` option on the CLI command, accepts multiple options.

```shell
falco test /path/to/main.vcl -o "client.class.checker=true" -o "client.as.name=overridden"
```


| Variable                                   | Tentative Value                    |
|:------------------------------------------:|:----------------------------------:|
| bereq.is_clustering                        | false                              |
| client.class.checker                       | false                              |
| client.class.downloader                    | false                              |
| client.class.feedreader                    | false                              |
| client.class.filter                        | false                              |
| client.class.masquerading                  | false                              |
| client.platform.mediaplayer                | false                              |
| client.geo.latitude                        | 37.7786941                         |
| client.geo.longitude                       | -122.3981452                       |
| client.as.number                           | 4294967294                         |
| client.as.name                             | "Reserved"                         |
| client.display.height                      | -1                                 |
| client.display.ppi                         | -1                                 |
| client.display.width                       | -1                                 |
| client.geo.area_code                       | 0                                  |
| client.geo.metro_code                      | 0                                  |
| client.geo.utc_offset                      | 0                                  |
| client.identified                          | false                              |
| client.requests                            | 1                                  |
| req.vcl.generation                         | 1                                  |
| req.vcl.version                            | 1                                  |
| workspace.bytes_free                       | 125008                             |
| workspace.bytes_total                      | 139392                             |
| workspace.overflowed                       | false                              |
| beresp.backend.src_ip                      | 127.0.0.1                          |
| client.geo.city                            | "unknown"                          |
| client.geo.city.ascii                      | "unknown"                          |
| client.geo.city.latin1                     | "unknown"                          |
| client.geo.city.utf8                       | "unknown"                          |
| client.geo.conn.speed                      | "unknown"                          |
| client.geo.conn.type                       | "unknown"                          |
| client.geo.continent_code                  | "unknown"                          |
| client.geo.country_code                    | "unknown"                          |
| client.geo.country_code3                   | "unknown"                          |
| client.geo.country_name                    | "unknown"                          |
| client.geo.country_name.ascii              | "unknown"                          |
| client.geo.country_name.latin1             | "unknown"                          |
| client.geo.country_name.utf8               | "unknown"                          |
| client.geo.ip_override                     | "unknown"                          |
| client.geo.postal_code                     | "unknown"                          |
| client.geo.proxy_description               | "unknown"                          |
| client.geo.proxy_type                      | "unknown"                          |
| client.geo.region                          | "unknown"                          |
| client.geo.region.ascii                    | "unknown"                          |
| client.geo.region.latin1                   | "unknown"                          |
| client.geo.region.utf8                     | "unknown"                          |
| client.platform.hwtype                     | (empty string)                     |
| server.datacenter                          | "FALCO"                            |
| server.hostname                            | "cache-localsimulator"             |
| server.identity                            | "cache-localsimulator"             |
| server.region                              | "US"                               |
| bereq.bytes_written                        | 0                                  |
| client.socket.cwnd                         | 60                                 |
| client.socket.nexthop                      | 127.0.0.1                          |
| client.socket.pace                         | 0                                  |
| client.socket.ploss                        | 0                                  |
| client.socket.cwnd                         | 60                                 |
| fastly_info.is_clueter_edge                | false                              |
| obj.is_pci                                 | false                              |
| req.backend.is_cluster                     | false                              |
| resp.is_locally_generated                  | false                              |
| req.digest.ratio                           | 0.4                                |
| obj.stale_white_revalidate                 | 60s                                |
| backend.socket.congestion_algorithm        | "cubic"                            |
| backend.socket.cwnd                        | 60                                 |
| backend.socket.tcpi_advmss                 | 0                                  |
| backend.socket.tcpi_bytes_acked            | 0                                  |
| backend.socket.tcpi_bytes_received         | 0                                  |
| backend.socket.tcpi_data_segs_in           | 0                                  |
| backend.socket.tcpi_data_segs_out          | 0                                  |
| backend.socket.tcpi_delivery_rate          | 0                                  |
| backend.socket.tcpi_delta_retrans          | 0                                  |
| backend.socket.tcpi_last_data_sent         | 0                                  |
| backend.socket.tcpi_max_pacing_rate        | 0                                  |
| backend.socket.tcpi_min_rtt                | 0                                  |
| backend.socket.tcpi_notsent_bytes          | 0                                  |
| backend.socket.tcpi_pacing_rate            | 0                                  |
| backend.socket.tcpi_pmtu                   | 0                                  |
| backend.socket.tcpi_rcv_mss                | 0                                  |
| backend.socket.tcpi_rcv_rtt                | 0                                  |
| backend.socket.tcpi_rcv_space              | 0                                  |
| backend.socket.tcpi_rcv_ssthresh           | 0                                  |
| backend.socket.tcpi_reordering             | 0                                  |
| backend.socket.tcpi_rtt                    | 0                                  |
| backend.socket.tcpi_rttvar                 | 0                                  |
| backend.socket.tcpi_segs_in                | 0                                  |
| backend.socket.tcpi_segs_out               | 0                                  |
| backend.socket.tcpi_snd_cwnd               | 0                                  |
| backend.socket.tcpi_snd_mss                | 0                                  |
| backend.socket.tcpi_snd_ssthresh           | 0                                  |
| backend.socket.tcpi_total_retrans          | 0                                  |
| backend.{name}.connections_open            | 0                                  |
| backend.{name}.connections_used            | 0                                  |
| backend.{name}.healthy                     | true                               |
| beresp.backend.alternate_ips               | (empty string)                     |
| beresp.backend.ip                          | 0                                  |
| beresp.backend.requests                    | 1                                  |
| client.socket.tcpi_snd_cwnd                | 0                                  |
| fastly_info.is_cluster_shield              | false                              |
| req.backend.is_origin                      | true                               |
| quic.cc.cwnd                               | 0                                  |
| quic.cc.ssthresh                           | 0                                  |
| quic.num_bytes.received                    | 0                                  |
| quic.num_bytes.sent                        | 0                                  |
| quic.num_packets.ack_received              | 0                                  |
| quic.num_packets.decryption_failed         | 0                                  |
| quic.num_packets.late_acked                | 0                                  |
| quic.num_packets.lost                      | 0                                  |
| quic.num_packets.received                  | 0                                  |
| quic.num_packets.sent                      | 0                                  |
| quic.rtt.latest                            | 0                                  |
| quic.rtt.minimum                           | 0                                  |
| quic.rtt.smoothed                          | 0                                  |
| quic.rtt.variance                          | 0                                  |
| client.socket.tcpi_advmss                  | 0                                  |
| client.socket.tcpi_bytes_acked             | 0                                  |
| client.socket.tcpi_bytes_received          | 0                                  |
| client.socket.tcpi_data_segs_in            | 0                                  |
| client.socket.tcpi_data_segs_out           | 0                                  |
| client.socket.tcpi_delivery_rate           | 0                                  |
| client.socket.tcpi_delta_retrans           | 0                                  |
| client.socket.tcpi_last_data_sent          | 0                                  |
| client.socket.tcpi_max_pacing_rate         | 0                                  |
| client.socket.tcpi_min_rtt                 | 0                                  |
| client.socket.tcpi_notsent_bytes           | 0                                  |
| client.socket.tcpi_pacing_rate             | 0                                  |
| client.socket.tcpi_pmtu                    | 0                                  |
| client.socket.tcpi_rcv_mss                 | 0                                  |
| client.socket.tcpi_rcv_rtt                 | 0                                  |
| client.socket.tcpi_rcv_space               | 0                                  |
| client.socket.tcpi_rcv_ssthresh            | 0                                  |
| client.socket.tcpi_reordering              | 0                                  |
| client.socket.tcpi_rtt                     | 0                                  |
| client.socket.tcpi_rttvar                  | 0                                  |
| client.socket.tcpi_segs_in                 | 0                                  |
| client.socket.tcpi_segs_out                | 0                                  |
| client.socket.tcpi_snd_cwnd                | 0                                  |
| client.socket.tcpi_snd_mss                 | 0                                  |
| client.socket.tcpi_snd_ssthresh            | 0                                  |
| client.socket.tcpi_total_retrans           | 0                                  |
| tls.client.ciphers_list_sha                | "JZtiTn8H/ntxORk+XXvU2EvNoz8="     |
| tls.client.ciphers_list                    | (Describe after the table)         |
| tls.client.ciphers_list_txt                | (Describe after the table)         |
| tls.client.ciphers_sha                     | "+7dB1w3Ov9S4Ct3HG3Qed68pSko="     |
| tls.client.handshake_sent_bytes            | 4759                               |
| tls.client.iana_chosen_cipher_id           | 49919                              |
| tls.client.ja3_md5                         | "582a3b42ab84f78a5b376b1e29d6d367" |
| tls.client.tlsexts_list                    | (empty string)                     |
| tls.client.tlsexts_list_sha                | (empty string)                     |
| tls.client.tlsexts_list_txt                | (empty string)                     |
| tls.client.tlsexts_sha                     | (empty string)                     |
| tls.client.certificate.dn                  | (empty string)                     |
| tls.client.certificate.is_cert_bad         | false                              |
| tls.client.certificate.is_cert_expired     | false                              |
| tls.client.certificate.is_cert_missing     | false                              |
| tls.client.certificate.is_cert_revoked     | false                              |
| tls.client.certificate.is_cert_unknown     | false                              |
| tls.client.certificate.is_unknown_ca       | false                              |
| tls.client.certificate.is_verified         | true                               |
| tls.client.certificate.issuer_dn           | (empty string)                     |
| tls.client.certificate.not_after           | Always 1 day before                |
| tls.client.certificate.not_before          | Always 1 year after                |
| tls.client.certificate.raw_certificate_b64 | (empty string)                     |
| tls.client.certificate.serial_number       | (empty string)                     |
| transport.bw_estimate                      | 0                                  |
| transpoty.type                             | "tcp"                              |
| waf.failures                               | 0                                  |
| waf.php_injection_score                    | 0                                  |
| waf.rce_score                              | 0                                  |
| fastly.is_staging                          | false                              |
| beresp.backend.src_port                    | 0                                  |
| fastly.ddos_detected                       | false                              |

`tls.client.ciphers_list` value is too long to fit the above table so we write the value following:

"130213031301C02FC02BC030C02C009EC0270067C028006B00A3009FCCA9CCA8CCAAC0AFC0ADC0A3C09FC05DC061C057C05300A2C0AEC0ACC0A2C09EC05CC060C056C052C024006AC0230040C00AC01400390038C009C01300330032009DC0A1C09DC051009CC0A0C09CC050003D003C0035002F00FF"

`tls.client.ciphers_list_txt` value is too long to fit the above table so we write the value following:

"TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_256_CCM:TLS_DHE_RSA_WITH_AES_256_CCM_8:TLS_DHE_RSA_WITH_AES_256_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384:TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384:TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:TLS_ECDHE_ECDSA_WITH_AES_128_CCM:TLS_DHE_RSA_WITH_AES_128_CCM_8:TLS_DHE_RSA_WITH_AES_128_CCM:TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256:TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_RSA_WITH_AES_256_CBC_SHA:TLS_DHE_DSS_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_RSA_WITH_AES_128_CBC_SHA:TLS_DHE_DSS_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_256_CCM_8:TLS_RSA_WITH_AES_256_CCM:TLS_RSA_WITH_ARIA_256_GCM_SHA384:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_128_CCM_8:TLS_RSA_WITH_AES_128_CCM:TLS_RSA_WITH_ARIA_128_GCM_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA256:TLS_RSA_WITH_AES_128_CBC_SHA256:TLS_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
```

These values will be updated when we find or implement a way to get accurate values.
