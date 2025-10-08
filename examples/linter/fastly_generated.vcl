# Noticing changes to your VCL? The event log
# (https://docs.fastly.com/en/guides/reviewing-service-activity-with-the-event-log)
# in the web interface shows changes to your service's configurations and the
# change log on developer.fastly.com (https://developer.fastly.com/reference/changes/vcl/)
# provides info on changes to the Fastly-provided VCL itself.

pragma optional_param geoip_opt_in true;
pragma optional_param max_object_size 2147483648;
pragma optional_param smiss_max_object_size 5368709120;
pragma optional_param fetchless_purge_all 1;
pragma optional_param chash_randomize_on_pass true;
pragma optional_param default_ssl_check_cert 1;
pragma optional_param max_backends 20;
pragma optional_param customer_id "bwIxaoVzhiEJrt4SIaIvT";
C!
W!
# Backends

backend F_Host_1 {
    .between_bytes_timeout = 10s;
    .connect_timeout = 1s;
    .dynamic = true;
    .first_byte_timeout = 15s;
    .host = "example.com";
    .max_connections = 200;
    .port = "443";
    .share_key = "qRK2E1vLIVkQ3BU0iVk9X7";

    .ssl = true;
    .ssl_cert_hostname = "example.com";
    .ssl_check_cert = always;
    .ssl_sni_hostname = "example.com";

    .probe = {
        .dummy = true;
        .initial = 5;
        .request = "HEAD / HTTP/1.1"  "Host: example.com" "Connection: close";
        .threshold = 1;
        .timeout = 2s;
        .window = 5;
      }
}
backend F_httpbin_org {
    .between_bytes_timeout = 10s;
    .connect_timeout = 1s;
    .dynamic = true;
    .first_byte_timeout = 15s;
    .host = "httpbin.org";
    .max_connections = 200;
    .port = "443";
    .share_key = "qRK2E1vLIVkQ3BU0iVk9X7";

    .ssl = true;
    .ssl_cert_hostname = "httpbin.org";
    .ssl_check_cert = always;
    .ssl_sni_hostname = "httpbin.org";

    .probe = {
        .dummy = true;
        .initial = 5;
        .request = "HEAD / HTTP/1.1"  "Host: httpbin.org" "Connection: close";
        .threshold = 1;
        .timeout = 2s;
        .window = 5;
      }
}





director ssl_shield_hnd_tokyo_jp shield {
   .shield = "hnd-tokyo-jp";
   .is_ssl = true;
}

director ssl_shield_tyo_tokyo_jp shield {
   .shield = "tyo-tokyo-jp";
   .is_ssl = true;
}



table example {
}

table my_example_dictionary {
    # REDACTED dictionary content
    # digest: db817286bc0c2af867c866e134641cc25b8b518913e8826dc952b9fc42e660b5
    # item_count: 1
    # last_updated: 2023-04-27 14:24:34
}










backend httpbin_org {
  .connect_timeout = 1s;
  .dynamic = true;
  .port = "443";
  .host = "httpbin.org";
  .first_byte_timeout = 20s;
  .max_connections = 500;
  .between_bytes_timeout = 20s;
  .share_key = "xei5lohleex3Joh5ie5uy7du";
  .ssl = true;
  .ssl_sni_hostname = "httpbin.org";
  .ssl_cert_hostname = "httpbin.org";
  .ssl_check_cert = always;
  .min_tls_version = "1.2";
  .max_tls_version = "1.2";
  //.bypass_local_route_table = false;
  .probe = {
    .request = "GET /status/200 HTTP/1.1" "Host: httpbin.org" "Connection: close";
    .dummy = true;
    .threshold = 1;
    .window = 2;
    .timeout = 5s;
    .initial = 1;
    .expected_response = 200;
    .interval = 10s;
  }
}

sub vcl_recv {
#--FASTLY RECV BEGIN
  if (req.restarts == 0) {
    if (!req.http.X-Timer) {
      set req.http.X-Timer = "S" time.start.sec "." time.start.usec_frac;
    }
    set req.http.X-Timer = req.http.X-Timer ",VS0";
  }

  if (req.http.Fastly-Orig-Accept-Encoding) {
    if (req.http.Fastly-Orig-Accept-Encoding ~ "\bbr\b") {
      set req.http.Accept-Encoding = "br";
    }
  }



  declare local var.fastly_req_do_shield BOOL;
  set var.fastly_req_do_shield = (req.restarts == 0);

# Snippet example_recv : 100
set req.http.Example-Recv = "1";

# Snippet my_dynamic_snippet_name : 100
if ( req.url ) { set req.http.my-snippet-test-header = "affirmative"; }

  # default conditions
  set req.backend = F_Host_1;

  if (!req.http.Fastly-SSL) {
     error 801 "Force SSL";
  }




    # end default conditions




      #do shield here F_Host_1 > ssl_shield_tyo_tokyo_jp;




  {
    if (req.backend == F_Host_1 && var.fastly_req_do_shield) {
      set req.backend = fastly.try_select_shield(ssl_shield_tyo_tokyo_jp, F_Host_1);
    }
  }
        #do shield here F_httpbin_org > ssl_shield_hnd_tokyo_jp;




  {
    if (req.backend == F_httpbin_org && var.fastly_req_do_shield) {
      set req.backend = fastly.try_select_shield(ssl_shield_hnd_tokyo_jp, F_httpbin_org);
    }
  }



#--FASTLY RECV END
  set req.http.Foo = "bar";
}

sub vcl_miss {
#--FASTLY MISS BEGIN


# this is not a hit after all, clean up these set in vcl_hit
  unset req.http.Fastly-Tmp-Obj-TTL;
  unset req.http.Fastly-Tmp-Obj-Grace;

  {
    if (req.http.Fastly-Check-SHA1) {
       error 550 "Doesnt exist";
    }

#--FASTLY BEREQ BEGIN
    {
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


 #;

    set req.http.Fastly-Cachetype = "MISS";

  }

#--FASTLY MISS END
}

sub vcl_hit {
#--FASTLY HIT BEGIN

# we cannot reach obj.ttl and obj.grace in deliver, save them when we can in vcl_hit
  set req.http.Fastly-Tmp-Obj-TTL = obj.ttl;
  set req.http.Fastly-Tmp-Obj-Grace = obj.grace;

  {
    set req.http.Fastly-Cachetype = "HIT";
  }

#--FASTLY HIT END
}

sub vcl_pass {
#--FASTLY PASS BEGIN


  {

#--FASTLY BEREQ BEGIN
    {
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


 #;
    set req.http.Fastly-Cachetype = "PASS";
  }

#--FASTLY PASS END
}

sub vcl_hash {

#--FASTLY HASH BEGIN

# support purge all
set req.hash += req.vcl.generation;
#--FASTLY HASH END
}

sub vcl_fetch {


#--FASTLY FETCH BEGIN



# record which cache ran vcl_fetch for this object and when
  set beresp.http.Fastly-Debug-Path = "(F " server.identity " " now.sec ") " if(beresp.http.Fastly-Debug-Path, beresp.http.Fastly-Debug-Path, "");

# generic mechanism to vary on something
  if (req.http.Fastly-Vary-String) {
    if (beresp.http.Vary) {
      set beresp.http.Vary = "Fastly-Vary-String, "  beresp.http.Vary;
    } else {
      set beresp.http.Vary = "Fastly-Vary-String, ";
    }
  }



#--FASTLY FETCH END

}

sub vcl_deliver {


#--FASTLY DELIVER BEGIN

# record the journey of the object, expose it only if req.http.Fastly-Debug.
  if (req.http.Fastly-Debug || req.http.Fastly-FF) {
    set resp.http.Fastly-Debug-Path = "(D " server.identity " " now.sec ") "
       if(resp.http.Fastly-Debug-Path, resp.http.Fastly-Debug-Path, "");

    set resp.http.Fastly-Debug-TTL = if(obj.hits > 0, "(H ", "(M ")
       server.identity
       if(req.http.Fastly-Tmp-Obj-TTL && req.http.Fastly-Tmp-Obj-Grace, " " req.http.Fastly-Tmp-Obj-TTL " " req.http.Fastly-Tmp-Obj-Grace " ", " - - ")
       if(resp.http.Age, resp.http.Age, "-")
       ") "
       if(resp.http.Fastly-Debug-TTL, resp.http.Fastly-Debug-TTL, "");

    set resp.http.Fastly-Debug-Digest = digest.hash_sha256(req.digest);
  } else {
    unset resp.http.Fastly-Debug-Path;
    unset resp.http.Fastly-Debug-TTL;
    unset resp.http.Fastly-Debug-Digest;
  }

  # add or append X-Served-By/X-Cache(-Hits)
  {

    if(!resp.http.X-Served-By) {
      set resp.http.X-Served-By  = server.identity;
    } else {
      set resp.http.X-Served-By = resp.http.X-Served-By ", " server.identity;
    }

    set resp.http.X-Cache = if(resp.http.X-Cache, resp.http.X-Cache ", ","") if(fastly_info.state ~ "HIT(?:-|\z)", "HIT", "MISS");

    if(!resp.http.X-Cache-Hits) {
      set resp.http.X-Cache-Hits = obj.hits;
    } else {
      set resp.http.X-Cache-Hits = resp.http.X-Cache-Hits ", " obj.hits;
    }

  }

  if (req.http.X-Timer) {
    set resp.http.X-Timer = req.http.X-Timer ",VE" time.elapsed.msec;
  }

  # VARY FIXUP
  {
    # remove before sending to client
    set resp.http.Vary = regsub(resp.http.Vary, "Fastly-Vary-String, ", "");
    if (resp.http.Vary ~ "^\s*$") {
      unset resp.http.Vary;
    }
  }
  unset resp.http.X-Varnish;


  # Pop the surrogate headers into the request object so we can reference them later
  set req.http.Surrogate-Key = resp.http.Surrogate-Key;
  set req.http.Surrogate-Control = resp.http.Surrogate-Control;

  # If we are not forwarding or debugging unset the surrogate headers so they are not present in the response
  if (!req.http.Fastly-FF && !req.http.Fastly-Debug) {
    unset resp.http.Surrogate-Key;
    unset resp.http.Surrogate-Control;
  }

  if(resp.status == 550) {
    return(deliver);
  }
  #default response conditions


# Header rewrite Generated by force TLS and enable HSTS : 100


      set resp.http.Strict-Transport-Security = "max-age=300";







#--FASTLY DELIVER END
}

sub vcl_error {
#--FASTLY ERROR BEGIN


  if (obj.status == 801) {
     set obj.status = 301;
     set obj.response = "Moved Permanently";
     set obj.http.Location = "https://" req.http.host req.url;
     synthetic {""};
     return (deliver);
  }




  if (req.http.Fastly-Restart-On-Error) {
    if (obj.status == 503 && req.restarts == 0) {
      restart;
    }
  }

  {
    if (obj.status == 550) {
      return(deliver);
    }
  }
#--FASTLY ERROR END


}

sub vcl_log {
#--FASTLY LOG BEGIN

  # default response conditions



#--FASTLY LOG END
}

sub vcl_pipe {
#--FASTLY PIPE BEGIN
  {


#--FASTLY BEREQ BEGIN
    {
      {
        if (req.http.Fastly-FF) {
          set bereq.http.Fastly-Client = "1";
        }
      }
      {
        # do not send this to the backend
        unset bereq.http.Fastly-Original-Cookie;
        unset bereq.http.Fastly-Original-URL;
        unset bereq.http.Fastly-Vary-String;
        unset bereq.http.X-Varnish-Client;
      }
      if (req.http.Fastly-Temp-XFF) {
         if (req.http.Fastly-Temp-XFF == "") {
           unset bereq.http.X-Forwarded-For;
         } else {
           set bereq.http.X-Forwarded-For = req.http.Fastly-Temp-XFF;
         }
         # unset bereq.http.Fastly-Temp-XFF;
      }
    }
#--FASTLY BEREQ END


    #;
    set req.http.Fastly-Cachetype = "PIPE";
    set bereq.http.connection = "close";
  }
#--FASTLY PIPE END

}

