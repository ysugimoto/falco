sub mod_recv {
  // Access restricted by allow ip ranges
  if (client.ip !~ internal_ips) {
    error 403;
  }
  
  // API Key Authentication
  declare local var.service STRING;
  set var.service = table.lookup(api_keys, req.http.Service-Api-Key);
  if (!var.service) {
    error 401;
  }
  set req.http.DeterminedService = var.service;
}
