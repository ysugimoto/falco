package interpreter

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/ysugimoto/falco/ast"
	"github.com/ysugimoto/falco/interpreter/context"
	"github.com/ysugimoto/falco/lexer"
	"github.com/ysugimoto/falco/parser"
)

const FastlyRecvMacro = `
#--FASTLY RECV BEGIN
if (req.restarts == 0) {
  if (!req.http.X-Timer) {
    set req.http.X-Timer = "S" time.start.sec "." time.start.usec_frac;
  }
  set req.http.X-Timer = req.http.X-Timer ",VS0";
}
#--FASTLY RECV END
`

const FastlyPassMacro = `
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
`

const FastlyHitMacro = `
#--FASTLY HIT BEGIN
# we cannot reach obj.ttl and obj.grace in deliver, save them when we can in vcl_hit
  set req.http.Fastly-Tmp-Obj-TTL = obj.ttl;
  set req.http.Fastly-Tmp-Obj-Grace = obj.grace;
  {
    set req.http.Fastly-Cachetype = "HIT";
  }
#--FASTLY HIT END
`

const FastlyMissMacro = `
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
`

const FastlyHashMacro = `
#--FASTLY HASH BEGIN
# support purge all
set req.hash += req.vcl.generation;
#--FASTLY HASH END
`

const FastlyFetchMacro = `
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
`

const FastlyErrorMacro = `
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
`

const FastlyDeliverMacro = `
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
#--FASTLY DELIVER END
`

const FastlyLogMacro = ""

var fastlyMacroExtractedVCLs = map[context.Scope]string{
	context.RecvScope:    FastlyRecvMacro,
	context.HitScope:     FastlyHitMacro,
	context.MissScope:    FastlyMissMacro,
	context.HashScope:    FastlyHashMacro,
	context.FetchScope:   FastlyFetchMacro,
	context.ErrorScope:   FastlyErrorMacro,
	context.DeliverScope: FastlyDeliverMacro,
	context.LogScope:     FastlyLogMacro,
}

func fastlyMacroVCLStatements(scope context.Scope) ([]ast.Statement, error) {
	macro, ok := fastlyMacroExtractedVCLs[scope]
	if !ok || macro == "" {
		return []ast.Statement{}, nil
	}

	l := lexer.NewFromString(
		strings.TrimSpace(macro)+"\n",
		lexer.WithFile("FastlyMacro::"+scope.String()),
	)
	statements, err := parser.New(l).ParseSnippetVCL()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return statements, nil
}
