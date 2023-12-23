sub vcl_recv {
  declare local var.is_null BOOL;
  declare local var.is_empty BOOL;
  declare local var.is_equal BOOL;

  declare local var.NOTSET STRING;
  declare local var.EMPTY STRING;
  declare local var.UNSET STRING;
  declare local var.SETNULL STRING;  # This process fails and results in EMPTY

  set var.EMPTY = "";
  set req.http.EMPTY = "";
  set req.http.VARS = "";
  set req.http.VARS:EMPTY = "";

  set var.UNSET = "V";
  set req.http.UNSET = "V";
  set req.http.VARS:UNSET = "V";
# unset var.UNSET;  # can't unset
  unset req.http.UNSET;
  unset req.http.VARS:UNSET;
  set var.SETNULL = req.http.UNDEF;

  if(!var.EMPTY){set var.is_null = true;}else{set var.is_null = false;}
  if(var.EMPTY==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(var.EMPTY==var.EMPTY){set var.is_equal = true;}else{set var.is_equal = false;}
  log "EMPTY var:" var.EMPTY "-" std.strlen(var.EMPTY) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.EMPTY){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.EMPTY==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.EMPTY==req.http.EMPTY){set var.is_equal = true;}else{set var.is_equal = false;}
  log "EMPTY header:" req.http.EMPTY "-" std.strlen(req.http.EMPTY) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.VARS:EMPTY){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.VARS:EMPTY==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.VARS:EMPTY==req.http.VARS:EMPTY){set var.is_equal = true;}else{set var.is_equal = false;}
  log "EMPTY VARS:" req.http.VARS:EMPTY "-" std.strlen(req.http.VARS:EMPTY) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!var.NOTSET){set var.is_null = true;}else{set var.is_null = false;}
  if(var.NOTSET==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(var.NOTSET==var.NOTSET){set var.is_equal = true;}else{set var.is_equal = false;}
  log "NOTSET var:" var.NOTSET "-" std.strlen(var.NOTSET) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.UNDEF){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.UNDEF==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.UNDEF==req.http.UNDEF){set var.is_equal = true;}else{set var.is_equal = false;}
  log "UNDEF header:" req.http.UNDEF "-" std.strlen(req.http.UNDEF) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.VARS:UNDEF){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.VARS:UNDEF==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.VARS:UNDEF==req.http.VARS:UNDEF){set var.is_equal = true;}else{set var.is_equal = false;}
  log "UNDEF VARS:" req.http.VARS:UNDEF "-" std.strlen(req.http.VARS:UNDEF) "-" var.is_null "-" var.is_empty "-" var.is_equal;

# if(!var.UNSET){set var.is_null = true;}else{set var.is_null = false;}
# if(var.UNSET==""){set var.is_empty = true;}else{set var.is_empty = false;}
# if(var.UNSET==var.UNSET){set var.is_equal = true;}else{set var.is_equal = false;}
# log "UNSET var:" var.UNSET "-" std.strlen(var.UNSET) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.UNSET){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.UNSET==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.UNSET==req.http.UNSET){set var.is_equal = true;}else{set var.is_equal = false;}
  log "UNSET header:" req.http.UNSET "-" std.strlen(req.http.UNSET) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!req.http.VARS:UNSET){set var.is_null = true;}else{set var.is_null = false;}
  if(req.http.VARS:UNSET==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(req.http.VARS:UNSET==req.http.VARS:UNSET){set var.is_equal = true;}else{set var.is_equal = false;}
  log "UNSET VARS:" req.http.VARS:UNSET "-" std.strlen(req.http.VARS:UNSET) "-" var.is_null "-" var.is_empty "-" var.is_equal;

  if(!var.SETNULL){set var.is_null = true;}else{set var.is_null = false;}
  if(var.SETNULL==""){set var.is_empty = true;}else{set var.is_empty = false;}
  if(var.SETNULL==var.SETNULL){set var.is_equal = true;}else{set var.is_equal = false;}
  log "SETNULL(fail) var:" var.SETNULL "-" std.strlen(var.SETNULL) "-" var.is_null "-" var.is_empty "-" var.is_equal;
}
