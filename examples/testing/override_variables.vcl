sub vcl_recv {
  #Fastly recv
  set req.http.Region = server.region;
}


sub overrides {
  // Following variables could be overridden by configuration
  set req.http.Is-Cert-Bad = tls.client.certificate.is_cert_missing;
  set req.http.Geo-Area-Code = client.geo.area_code;
  set req.http.Digest-Ratio = req.digest.ratio;
  set req.http.Client-As-Name = client.as.name;
}
