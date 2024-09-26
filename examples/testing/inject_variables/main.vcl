sub vcl_recv {
  if (client.geo.country_code == "JP") {
    return (pass);
  }
  return (lookup);
}
