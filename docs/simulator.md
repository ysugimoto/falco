# Local Simulator

`falco` enables to run simulate server which evaluates your VCLs like Fastly does whith our own VCL interpreter.
You can start local simulate as following:

```shell
falco local /path/to/your/default.vcl
```

Then local server starts on http://localhost:3124, you can send HTTP request via curl, browser, etc.
The server response is JSON which indicates VCL process information, it includes:

- VCL subroutine flow, what subroutine has processed with request/response information
- Entire `log` statement output
- Restart count
- Determined backend
- Served by cached object or not
- Processing time

Paticularly VCL subroutine flow is useful for debugging.

## Important

falco's interpreter is just a `simulator`, so we could not be depicted Fastly's actual behavior.
There are many limitations which are described below.

## Debug mode

`falco` also includes TUI debugger so that you can debug VCL with step execution.
You can run debugger with providing `-debug` option on simulator:

```
falco local -debug /path/to/your/default.vcl
```

### Start debugging

When falco runs simulator with debugger, find `@debugger` leading annotation comment in your VCL.
If falco finds that, stop execution on the statement, for example:

```vcl
sub vcl_recv {
  #FASTLY RECV

  // @debugger
  set req.backend = example; <- stop on this statement
  ...
}
```

And the the debugger TUI accepts function keys to step execution:

- `F7`: resume execution to the next annotation comment
- `F8`: step in
- `F9`: step over
- `F10`: step out

And you can type other keys to investigate some variables in debugger shell.

[screenshot]

## Simulator Limitations

The simulator has a lot of limitations, of course Fastly edge cloud behaivor is undocumented and local environment reason.
As long as we reproduce Varnish lifecycle which is described [here](https://developer.fastly.com/learning/vcl/using/), and guess and suspect the behaivor but some of variables are set as virtual value.

Limitations are following:

- Even adding `Fastly-Debug` header, debug header values are fake because  we could not know what DataCenter is choosed
- Origin-Shielding and clustering fetch related features are ingored
- Cache object is not stored persistently, only manages in-memory so process are killed, all cache objects are deleted
- `Stale-While-Revalidate` does not work
- Extracted VCL in Faslty boilerplate marco is different. Only extracts VCL snippets
- May not add some of Fastly specific request/response headers
- WAF does not work
- ESI will not work correctly
- Director choosing algorithm result may be different
- All of backends always treats healthy
- Lots of predefined variables and builtin functions returns empty or tentative value

Unsupporeted variables, returns tentative value describes following table:

| Variable                            | Tentative Value        |
|:===================================:|:======================:|
| bereq.is_clustering                 | false                  |
| client.class.checker                | false                  |
| client.class.downloader             | false                  |
| client.class.feedreader             | false                  |
| client.class.filter                 | false                  |
| client.class.masquerading           | false                  |
| client.platform.mediaplayer         | false                  |
| client.geo.latitude                 | 37.7786941             |
| client.geo.longitude                | -122.3981452           |
| client.as_number                    | 4294967294             |
| client.as_name                      | "Reserved"             |
| client.display.height               | -1                     |
| client.display.ppi                  | -1                     |
| client.display.width                | -1                     |
| client.geo.area_code                | 0                      |
| client.geo.metro_code               | 0                      |
| client.geo.utc_offset               | 0                      |
| client.identified                   | false                  |
| client.requests                     | 1                      |
| req.vcl.generation                  | 1                      |
| req.vcl.version                     | 1                      |
| workspace.bytes_free                | 125008                 |
| workspace.bytes_total               | 139392                 |
| workspace.overflowed                | false                  |
| beresp.backend.src_ip               | 127.0.0.1              |
| client.geo.city                     | "unknown"              |
| client.geo.city.ascii               | "unknown"              |
| client.geo.city.latin1              | "unknown"              |
| client.geo.city.utf8                | "unknown"              |
| client.geo.conn.speed               | "unknown"              |
| client.geo.conn.type                | "unknown"              |
| client.geo.continent_code           | "unknown"              |
| client.geo.country_code             | "unknown"              |
| client.geo.country_code3            | "unknown"              |
| client.geo.country_name             | "unknown"              |
| client.geo.country_name.ascii       | "unknown"              |
| client.geo.country_name.latin1      | "unknown"              |
| client.geo.country_name.utf8        | "unknown"              |
| client.geo.ip_override              | "unknown"              |
| client.geo.postal_code              | "unknown"              |
| client.geo.proxy_description        | "unknown"              |
| client.geo.proxy_type               | "unknown"              |
| client.geo.region                   | "unknown"              |
| client.geo.region.ascii             | "unknown"              |
| client.geo.region.latin1            | "unknown"              |
| client.geo.region.utf8              | "unknown"              |
| client.platform.hwtype              | (empty string)         |
| server.datacenter                   | "FALCO"                |
| server.hostname                     | "cache-localsimulator" |
| server.identity                     | "cache-localsimulator" |
| server.region                       | "US"                   |
| bereq.bytes_written                 | 0                      |
| client.socket.cwnd                  | 60                     |
| client.socket.nexthop               | 127.0.0.1              |
| client.socket.pace                  | 0                      |
| client.socket.ploss                 | 0                      |
| client.socket.cwnd                  | 60                     |
| fastly_info.is_clueter_edge         | false                  |
| obj.is_pci                          | false                  |
| req.backend.is_cluster              | false                  |
| resp.is_locally_generated           | false                  |
| req.digest_ratio                    | 0.4                    |
| obj.stale_white_revalidate          | 60s                    |
| waf.blocked                         | false                  |
| waf.executed                        | false                  |
| waf.failures                        | 0                      |
| waf.logged                          | false                  |
| waf.passed                          | false                  |
| backend.socket.congestion_algorithm | "cubic"                |
| backend.socket.cwnd                 | 60                     |
| backend.socket.tcpi_advmss          | 0                      |
| backend.socket.tcpi_bytes_acked     | 0                      |
| backend.socket.tcpi_bytes_received  | 0                      |
| backend.socket.tcpi_data_segs_in    | 0                      |
| backend.socket.tcpi_data_segs_out   | 0                      |
| backend.socket.tcpi_delivery_rate   | 0                      |
| backend.socket.tcpi_delta_retrans   | 0                      |
| backend.socket.tcpi_last_data_sent  | 0                      |
| backend.socket.tcpi_max_pacing_rate | 0                      |
| backend.socket.tcpi_min_rtt         | 0                      |
| backend.socket.tcpi_notsent_bytes   | 0                      |
| backend.socket.tcpi_pacing_rate     | 0                      |
| backend.socket.tcpi_pmtu            | 0                      |
| backend.socket.tcpi_rcv_mss         | 0                      |
| backend.socket.tcpi_rcv_rtt         | 0                      |
| backend.socket.tcpi_rcv_space       | 0                      |
| backend.socket.tcpi_rcv_ssthresh    | 0                      |
| backend.socket.tcpi_reordering      | 0                      |
| backend.socket.tcpi_rtt             | 0                      |
| backend.socket.tcpi_rttvar          | 0                      |
| backend.socket.tcpi_segs_in         | 0                      |
| backend.socket.tcpi_segs_out        | 0                      |
| backend.socket.tcpi_snd_cwnd        | 0                      |
| backend.socket.tcpi_snd_mss         | 0                      |
| backend.socket.tcpi_snd_ssthresh    | 0                      |
| backend.socket.tcpi_total_retrans   | 0                      |
| beresp.backend.alternate_ips        | (empty string)         |
| beresp.backend.ip                   | 0                      |
| beresp.backend.requests             | 1                      |
| client.socket.tcpi_snd_cwnd         | 0                      |
| fastly_info.is_cluster_shield       | false                  |
| req.backend.is_origin               | true                   |
| quic.cc.cwnd                        | 0                      |
| quic.cc.ssthresh                    | 0                      |
| quic.num_bytes.received             | 0                      |
| quic.num_bytes.sent                 | 0                      |
| quic.num_packets.ack_received       | 0                      |
| quic.num_packets.decryption_failed  | 0                      |
| quic.num_packets.late_acked         | 0                      |
| quic.num_packets.lost               | 0                      |
| quic.num_packets.received           | 0                      |
| quic.num_packets.sent               | 0                      |
| quic.rtt.latest                     | 0                      |
| quic.rtt.minimum                    | 0                      |
| quic.rtt.smoothed                   | 0                      |
| quic.rtt.variance                   | 0                      |
