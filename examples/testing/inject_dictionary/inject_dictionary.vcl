sub vcl_recv {
  // Dictionary will be injected by testing configurations.
  if (table.lookup(injected_dictionary, "is_maintenance") == "1") {
    return(pass);
  }
  return(lookup);
}
