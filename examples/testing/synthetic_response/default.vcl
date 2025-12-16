sub vcl_error {
  synthetic "No dice.";
  set obj.response = "Overwritten";
}
