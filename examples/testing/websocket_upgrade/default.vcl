sub vcl_recv {
  #FASTLY RECV
  // req.http.Upgrade is protected in the simulator, so tests trigger the
  // upgrade path with a custom header instead
  if (req.http.X-Upgrade == "websocket") {
    return (upgrade);
  }
  return (lookup);
}
