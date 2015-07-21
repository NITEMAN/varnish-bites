/* Varnish 3 example config for Drupal 7 / Pressflow 6 & 7 */
# Original source: https://github.com/NITEMAN/varnish-bites/varnish4/drupal-base.vcl
# Copyright (c) 2015 Pedro González Serrano and individual contributors.
# MIT License

# Intended to be used both in simple production environments and with learning/teaching purposes.
# Loosely based on http://www.lullabot.com/sites/default/files/default_varnish3.vcl_.txt

/* Backend probes / healthchecks */
# See https://www.varnish-cache.org/docs/3.0/reference/vcl.html#backend-probes
probe basic {
  /* Only test that backend's IP serves content for '/' */
  # This might be a too heavy probe
  # .url = "/";
  /* Only test that backend's IP has apache working */
  # Nginx would fail this probe with a default config
  .request =
    "OPTIONS * HTTP/1.1"
    "Host: *"
    "Connection: close";
  .interval = 10s;
  .timeout = 2s;
  .window = 8;
  .threshold = 6;
}


/* Backend definitions.*/
# See https://www.varnish-cache.org/docs/3.0/reference/vcl.html#backend-declarations
backend default {
  /* Default backend on the same machine. WARNING: timeouts could be not big enought for certain POST request */
  .host = "127.0.0.1";
  .port = "8008";
  .connect_timeout = 60s;
  .first_byte_timeout = 60s;
  .between_bytes_timeout = 60s;
  .probe = basic;
}


/* Directors. */
# See https://www.varnish-cache.org/docs/3.0/reference/vcl.html#directors
# Empty in simple configs


/* Access Control Lists */
# See https://www.varnish-cache.org/docs/3.0/reference/vcl.html#acls
acl purge_ban {
  /* Simple access control list for allowing item purge for the self machine */
  "127.0.0.1"/32; // We can use '"localhost";' instead
}
acl allowed_monitors {
  /* Simple access control list for allowing item purge for the self machine */
  "127.0.0.1"/32; // We can use'"localhost";' instead
}
acl own_proxys {
  "127.0.0.1"/32; // We can use'"localhost";' instead
}


/* Custom routines */
# Empty in simple configs.
# We can name subs with no restrictions but as a task can need several chunks of code in diferent states,
# it's a good idea to identify what main sub will call each with a suffix.
# /* Example 301 client redirection removing "www" prefix from request */
# sub perm_redirections_recv {
#   if ( req.http.host ~ "^www.*$" ) {
#     error 751 "http://" + regsub(req.http.host, "^www\.", "") + req.url;
#   }
# }
# sub perm_redirections_error {
#   if (obj.status == 751) {
#     /* Get new URL from the response */
#     set obj.http.Location = obj.response;
#     /* Set HTTP 301 for permanent redirect */
#     set obj.status = 301;
#     return(deliver);
#   }
# }


/* VCL logigc overrides */
# Note that the built-in logic will be appended to our code if no return is performed before.
# Built-in logic is included commented out right after our's for reference purposes in that cases.
# See https://www.varnish-cache.org/trac/wiki/VCLExampleDefault
# See https://www.varnish-cache.org/docs/3.0/reference/vcl.html#subroutines

# vcl_recv: Called at the beginning of a request, after the complete request has been received and parsed.
# Its purpose is to decide whether or not to serve the request, how to do it, and, if applicable, which backend to use.
sub vcl_recv {
  /* 0th: general bypass, general return & authorization checks */
  # Empty in simple configs.
  # Useful for debugging we can pipe or pass the request to default backend here to bypass completely Varnish.
  # return (pipe);
  # return (pass);
  # We can also return here a 200 Ok for network performance benchmarking.
  # error 200 "Ok";
  # Finally we can perform basic HTTP authentification here by example.
  # See http://blog.tenya.me/blog/2011/12/14/varnish-http-authentication/

  /* 1st: Check for Varnish special requests */ 
  # Purge logic.
  # See https://www.varnish-cache.org/docs/3.0/tutorial/purging.html#http-purges
  # See https://www.varnish-software.com/static/book/Cache_invalidation.html#removing-a-single-object
  if (req.request == "PURGE") {
    if (!client.ip ~ purge_ban) {
      error 405 "Not allowed.";
    }
    return (lookup);
  }
  # Ban logic. See https://www.varnish-cache.org/docs/3.0/tutorial/purging.html#bans
  if (req.request == "BAN") {
    if (!client.ip ~ purge_ban) {
      error 405 "Not allowed.";
    }
    ban("req.http.host == " + req.http.host +
      "&& req.url == " + req.url);    
    error 200 "Ban added";
  }
  # Custom response implementation example in order to check that Varnish is working properly.
  # This is usefull for automatic monitoring with monit or when Varnish is behind another proxies like HAProxy.
  if ( ( req.http.host == "monitor.server.health"
      || req.http.host == "health.varnish" )
    && client.ip ~ allowed_monitors
    && ( req.request == "OPTIONS" || req.request == "GET" )
    ) {
    error 200 "Ok";
  }

  /* 2nd: Do some Varnish black magic such as custom client redirections */
  # Empty in simple configs.
  # call perm_redirections_recv;
  # Here we can also enforce SSL when Varnish run behind some SSL termination point.

  /* 3rd: Time for backend choice */
  # Empty in simple configs.

  /* 4th: Set custom headers for backend like X-Forwarded-For (copied from built-in logic) */
  if ( req.restarts == 0 ) {
    /* See also vcl_pipe section */
    if ( ! client.ip ~ own_proxys ) {
      if ( req.http.x-forwarded-for ) {
        set req.http.X-Forwarded-For = req.http.X-Forwarded-For + ", " + client.ip;
      } else {
        set req.http.X-Forwarded-For = client.ip;
      }
    }
  }

  /* 5th: Bypass breakpoint 1 */
  # Useful for debugging we can now pipe or pass the request to backend with headers setted.
  # return (pipe);
  # return (pass);

  /* 6th: Decide if we should deal with a request (mostly copied from built-in logic) */
  if (req.request != "GET" &&
      req.request != "HEAD" &&
      req.request != "PUT" &&
      req.request != "POST" &&
      req.request != "TRACE" &&
      req.request != "OPTIONS" &&
      req.request != "DELETE") {
    /* Non-RFC2616 or CONNECT which is weird. */
    return (pipe);
  }
  if (req.request != "GET" && req.request != "HEAD") {
    /* We only deal with GET and HEAD by default */
    return (pass);
  }
  if (req.http.Authorization) {
    /* Not cacheable by default */
    return (pass);
  }

  /* 7th: Access control for some URLs by ACL */
  # Empty in simple configs.
  # By example denial some URLs depending on client-ip, we'll need to define corresponding ACL 'internal'.
  # if (req.url ~ "^/(cron|install)\.php$" && !client.ip ~ internal) {
  #   # Have Varnish throw the error directly.
  #   error 403 "Forbidden.";
  #   # Use a custom error page that you've defined in Drupal at the path "404".
  #   # set req.url = "/403";
  # }

  /* 8th: Custom exceptions */
  # Host exception example:
  # if (req.http.host == "ejemplo.exception.com") {
  #     return (pass);
  # }
  # Drupal exceptions, edit if we want to cache some AJAX/AHAH request.
  # Add here filters for never cache URLs such as Payment Gateway's callbacks
  if (req.url ~ "^/status\.php$" ||
      req.url ~ "^/update\.php$" ||
      req.url ~ "^/ooyala/ping$" ||
      req.url ~ "^/admin/build/features" ||
      req.url ~ "^/info/.*$" ||
      req.url ~ "^/flag/.*$" ||
      req.url ~ "^.*/ajax/.*$" ||
      req.url ~ "^.*/ahah/.*$") {
    /* Do not cache these paths */
    return (pass);
  }
  # Pipe these paths directly to backend for streaming.
  if (req.url ~ "^/admin/content/backup_migrate/export") {
    return (pipe);
  }
  if (req.url ~ "^/system/files") {
    return (pipe);
  }

  /* 9th: Enable grace mode */
  # See https://www.varnish-cache.org/docs/3.0/tutorial/handling_misbehaving_servers.html#grace-mode
  if (! req.backend.healthy) {
    /* Use a longer grace period if all backends are down */
    set req.grace = 1h;
    /* Use anonymous, cached pages if all backends are down. */
    unset req.http.Cookie;
    # TO-DO: Add sick marker
  } else {
    /* Allow the backend to serve up stale content if it is responding slowly. */
    set req.grace = 30s;
  }

  /* 10th: Deal with compression and the Accept-Encoding header */
  # Althought Varnish 3 handles gziped content itself by default, just to be sure we want to 
  # remove Accept-Encoding for some compressed formats.
  # See https://www.varnish-cache.org/docs/3.0/phk/gzip.html#what-does-http-gzip-support-do
  # See https://www.varnish-cache.org/docs/3.0/tutorial/compression.html
  # See https://www.varnish-cache.org/docs/3.0/reference/varnishd.html?highlight=http_gzip_support
  # See (for older configs) https://www.varnish-cache.org/trac/wiki/VCLExampleNormalizeAcceptEncoding
  if (req.http.Accept-Encoding) {
    if ( req.url ~ "(?i)\.(7z|avi|bz2|flv|gif|gz|jpe?g|mpe?g|mk[av]|mov|mp[34]|og[gm]|pdf|png|rar|swf|tar|tbz|tgz|woff2?|zip|xz)(\?.*)?$"
      /* Already compressed formats, no sense trying to compress again */
      remove req.http.Accept-Encoding;
    }
  }

  /* 11th: Another header manipulation */
  # Empty in simple configs.
  # We could add here a custom header grouping User-agent families.

  /* 12th: Cookie removal */
  # Always cache the following static file types for all users. 
  # Use with care if we control certain downloads depending on cookies. 
  # Be carefull also if appending .htm[l] via Drupal's clean URLs.
  if ( req.url ~ "(?i)\.(bz2|css|eot|gif|gz|html?|ico|jpe?g|js|mp3|ogg|otf|pdf|png|rar|svg|swf|tbz|tgz|ttf|woff2?|zip)(\?(itok=)?[a-z0-9_=\.\-]+)?$"
    && req.url !~ "/system/storage/serve"
  ) {
      unset req.http.Cookie;
  }
  # Remove all cookies that backend doesn't need to know about.
  # See https://www.varnish-cache.org/trac/wiki/VCLExampleRemovingSomeCookies
  if (req.http.Cookie) {
    /* Warning: Not a pretty solution */
    /* Prefix header containing cookies with ';' */
    set req.http.Cookie = ";" + req.http.Cookie;
    /* Remove any spaces after ';' in header containing cookies */
    set req.http.Cookie = regsuball(req.http.Cookie, "; +", ";");
    /* Prefix cookies we want to preserve with one space */
    /* 'S{1,2}ESS[a-z0-9]+' is the regular expression matching a Drupal session cookie ({1,2} added for HTTPS support) */
    /* 'NO_CACHE' is usually set after a POST request to make sure issuing user see the results of his post */
    /* 'OATMEAL' & 'CHOCOLATECHIP' are special cookies used by Drupal's Bakery module to provide Single Sign On */
    /* Keep in mind we should add here any cookie that should reach the backend such as splahs avoiding cookies */
    set req.http.Cookie = regsuball(req.http.Cookie, ";(S{1,2}ESS[a-z0-9]+|NO_CACHE|OATMEAL|CHOCOLATECHIP)=", "; \1=");
    /* Remove from the header any single Cookie not prefixed with a space until next ';' separator */
    set req.http.Cookie = regsuball(req.http.Cookie, ";[^ ][^;]*", "");
    /* Remove any '; ' at the start or the end of the header */
    set req.http.Cookie = regsuball(req.http.Cookie, "^[; ]+|[; ]+$", "");

    if (req.http.Cookie == "") {
      /* If there are no remaining cookies, remove the cookie header. */
      unset req.http.Cookie;
    }
  }

  /* 13th: Session cookie & special cookies bypass caching stage */
  # As we might want to cache some requests, hashed with its cookies, 
  # we don't simply pass when some cookies remain present at this point.
  # Instead we look for request that must be passed due to the cookie header.
  if (req.http.Cookie ~ "SESS" ||
      req.http.Cookie ~ "SSESS" ||
      req.http.Cookie ~ "NO_CACHE" ||
      req.http.Cookie ~ "OATMEAL" ||
      req.http.Cookie ~ "CHOCOLATECHIP") {
    return (pass);
  }

  /* 14th: Bypass breakpoint 2 */
  # Useful for debugging we can now pipe or pass the request to backend to bypass cache.
  # return (pipe);
  # return (pass);

  /* 15th: Bypass built-in logic */
  # We make sure no built-in logic is processed after ours returning a lookup.
  return (lookup);
}

# vcl_pipe: Called upon entering pipe mode.
# In this mode, the request is passed on to the backend, 
# and any further data from either client or backend is passed on unaltered until either end closes the connection.
sub vcl_pipe {
  /* Prevent connection re-using for piped requests */
  # Note that only the first request to the backend will have X-Forwarded-For set.
  # As we use X-Forwarded-For and want to have it set for all requests, 
  # we have to make sure connection won't be reused after the request.
  # It is not set by default as it might break some broken web applications, like IIS with NTLM authentication.
  # See https://www.varnish-cache.org/trac/wiki/VCLExamplePipe
  # TO-DO: make sure this is compatible with websockets piping,
  # reference https://www.varnish-cache.org/docs/3.0/tutorial/websockets.html
  set bereq.http.connection = "close";

  /* Bypass built-in logic */
  # We make sure no built-in logic is processed after ours returning at this point.
  return (pipe);
}

# vcl_pass: Called upon entering pass mode. 
# In this mode, the request is passed on to the backend, and the backend's response is passed on to the client, 
# but is not entered into the cache.
# Subsequent requests submitted over the same client connection are handled normally.
# sub vcl_pass {
#     return (pass);
# }

# vcl_hash: You may call hash_data() on the data you would like to add to the hash.
# Hash is used by Varnish to uniquely identify objects.
sub vcl_hash {
  /* Hash cookie data */
  # As requests with same URL and host can produce diferent results when issued with different cookies,
  # we need to store items hashed with the associated cookies. Note that cookies are already sanitized when we reach this point.
  if (req.http.Cookie) {
    /* Include cookie in cache hash */
    hash_data(req.http.Cookie);
  }

  /* Custom header hashing */
  # Empty in simple configs.
  # Example for caching differents object versions by device previously detected (when static content could also vary):
  # if (req.http.X-UA-Device) {
  #   hash_data(req.http.X-UA-Device);
  # }
  # Example for caching diferent object versions by X-Forwarded-Proto, trying to be smart about what kind of request
  # could generate diffetent responses.
  if ( req.http.X-Forwarded-Proto
    && req.url !~ "(?i)\.(bz2|css|eot|gif|gz|html?|ico|jpe?g|js|mp3|ogg|otf|pdf|png|rar|svg|swf|tbz|tgz|ttf|woff2?|zip)(\?(itok=)?[a-z0-9_=\.\-]+)?$"
    hash_data(req.http.X-Forwarded-Proto);
  }

  /* Continue with built-in logic */
  # We want built-in logic to be processed after ours so we don't call return.
}
# sub vcl_hash {
#     hash_data(req.url);
#     if (req.http.host) {
#         hash_data(req.http.host);
#     } else {
#         hash_data(server.ip);
#     }
#     return (hash);
# }

# vcl_hit: Called after a cache lookup if the requested document was found in the cache.
sub vcl_hit {
  /* Check for Varnish special requests */ 
  # Purge logic.
  # See https://www.varnish-cache.org/docs/3.0/tutorial/purging.html#http-purges
  # See https://www.varnish-software.com/static/book/Cache_invalidation.html#removing-a-single-object
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }

  /* Continue with built-in logic */
  # We want built-in logic to be processed after ours so we don't call return.
}
# sub vcl_hit {
#     return (deliver);
# }

# vcl_miss: Called after a cache lookup if the requested document was not found in the cache.
# Its purpose is to decide whether or not to attempt to retrieve the document from the backend, and which backend to use.
sub vcl_miss {
  /* Check for Varnish special requests */ 
  # Purge logic.
  # See https://www.varnish-cache.org/docs/3.0/tutorial/purging.html#http-purges
  # See https://www.varnish-software.com/static/book/Cache_invalidation.html#removing-a-single-object
  if (req.request == "PURGE") {
    purge;
    error 200 "Purged.";
  }

  /* Continue with built-in logic */
  # We want built-in logic to be processed after ours so we don't call return.
}
# sub vcl_miss {
#     return (fetch);
# }

# vcl_fetch: Called after a document has been successfully retrieved from the backend.
sub vcl_fetch {
  /* Caching exceptions */
  # Varnish will cache objects with response codes: 200, 203, 300, 301, 302, 307, 404 & 410.
  # See https://www.varnish-software.com/static/book/VCL_Basics.html#the-initial-value-of-beresp-ttl
  # Drupal's Imagecache module can return a 307 redirection to the requested url itself and, depending on Drupal's cache settings,
  # this could lead to a redirection loop being cached for a long time but also we want Varnish to shield a little the backend.
  # See http://drupal.org/node/1248010
  # See http://drupal.org/node/310656
  if (beresp.status == 307 &&
      /* TO-DO: verify that this work better than 'req.url ~ "imagecache"' */
      beresp.http.Location == req.url &&
      beresp.ttl > 5s) {
    set beresp.ttl = 5s;
    set beresp.http.cache-control = "max-age=5";
  }

  /* Enable grace mode. Related with our 9th stage on vcl_recv */
  # See https://www.varnish-cache.org/docs/3.0/tutorial/handling_misbehaving_servers.html#grace-mode
  set beresp.grace = 1h;

  /* Enable saint mode. Related with our 9th stage on vcl_recv */
  # See https://www.varnish-cache.org/docs/3.0/tutorial/handling_misbehaving_servers.html#saint-mode
  if (beresp.status == 500) {
    set beresp.saintmode = 20s;
    # TO-DO: consider not restarting POST requests as seen on https://www.varnish-cache.org/trac/wiki/VCLExampleSaintMode
    return(restart);
  }

  /* Strip cookies from the following static file types for all users. Related with our 12th stage on vcl_recv */
  if ( req.url ~ "(?i)\.(bz2|css|eot|gif|gz|html?|ico|jpe?g|js|mp3|ogg|otf|pdf|png|rar|svg|swf|tbz|tgz|ttf|woff2?|zip)(\?(itok=)?[a-z0-9_=\.\-]+)?$"
    unset beresp.http.set-cookie;
  }

  /* Gzip response */
  # Empty in simple configs
  # Use Varnish to Gzip respone, if suitable, before storing it on cache
  # See https://www.varnish-cache.org/docs/3.0/tutorial/compression.html
  # See https://www.varnish-cache.org/docs/3.0/phk/gzip.html
  if (! beresp.http.Content-Encoding &&
      (beresp.http.content-type ~ "text" ||
       beresp.http.content-type ~ "application/x-javascript" ||
       beresp.http.content-type ~ "application/javascript" ||
       beresp.http.content-type ~ "application/rss+xml" ||
       beresp.http.content-type ~ "application/xml" ||
       beresp.http.content-type ~ "Application/JSON")
  ) {
    set beresp.do_gzip = true;
    if ( beresp.http.Vary ) {
      if ( ! beresp.http.Vary ~ "Accept-Encoding" ) {
        set beresp.http.Vary = beresp.http.Vary + ",Accept-Encoding";
      }
    } else {
      set beresp.http.Vary = "Accept-Encoding";
    }
  }

  /* Debugging headers */
  # Please consider the risks of showing publicly this information, we can wrap this with an ACL
  # We can add the name of the backend that has processed the request:
  # set beresp.http.X-Backend = beresp.backend.name;
  # We can use a header to tell if the object was gziped by Varnish
  # if (beresp.do_gzip) {
  #   set beresp.http.X-Varnish-Gzipped = "yes";
  # } else {
  #   set beresp.http.X-Varnish-Gizipped = "no";
  # }
  # We can also add headers informing whether the object is cacheable or not and why.
  # https://www.varnish-cache.org/trac/wiki/VCLExampleHitMissHeader#Varnish3.0
  if (beresp.ttl <= 0s) {
    /* Varnish determined the object was not cacheable */
    set beresp.http.X-Cacheable = "NO:Not Cacheable";
  } elsif (req.http.Cookie ~ "(SESS|SSESS|NO_CACHE|OATMEAL|CHOCOLATECHIP)") {
    /* We don't wish to cache content for logged in users or with certain cookies. Related with our 9th stage on vcl_recv */
    set beresp.http.X-Cacheable = "NO:Cookies";
    # return(hit_for_pass);
  } elsif (beresp.http.Cache-Control ~ "private") {
    /* We are respecting the Cache-Control=private header from the backend */
    set beresp.http.X-Cacheable = "NO:Cache-Control=private";
    # return(hit_for_pass);
  } else {
    /* Varnish determined the object was cacheable */
    set beresp.http.X-Cacheable = "YES";
  }

  /* Further header manipulation */
  # Empty in simple configs.
  # We can also unset some headers to prevent information disclosure and save some cache space
  # unset beresp.http.Server;
  # unset beresp.http.X-Powered-By;

  /* Continue with built-in logic */
  # We want built-in logic to be processed after ours so we don't call return.
}
# sub vcl_fetch {
#     if (beresp.ttl <= 0s ||
#         beresp.http.Set-Cookie ||
#         beresp.http.Vary == "*") {
#               /*
#                * Mark as "Hit-For-Pass" for the next 2 minutes
#                */
#               set beresp.ttl = 120 s;
#               return (hit_for_pass);
#     }
#     return (deliver);
# }

# vcl_deliver: Called before an object is delivered to the client
sub vcl_deliver {
  /* Debugging headers */
  # Please consider the risks of showing publicly this information, we can wrap this with an ACL
  # Add whether the object is a cache hit or miss and the number of hits for the object.
  # https://www.varnish-cache.org/trac/wiki/VCLExampleHitMissHeader#Addingaheaderindicatinghitmiss
  if (obj.hits > 0) {
    set resp.http.X-Cache = "HIT";
    set resp.http.X-Cache-Hits = obj.hits;
  } else {
    set resp.http.X-Cache = "MISS";
    /* Show the results of cookie sanitization */
    set resp.http.X-Cookie = req.http.Cookie;
  }
  # TO-DO: Add sick marker
  # Restart count
  if ( req.restarts > 0) {
    set resp.http.X-Restarts = req.restarts;
  }
  # Add the Varnish server hostname
  set resp.http.X-Varnish-Server = server.hostname;
  # If we have setted a custom header with device family detected we can show it:
  # if (req.http.X-UA-Device) {
  #   set resp.http.X-UA-Device = req.http.X-UA-Device;
  # }
  # If we have recived a custom header with the protocol in the request we can show it:
  # if (req.http.X-Forwarded-Proto) {
  #   set resp.http.X-Forwarded-Proto = req.http.X-Forwarded-Proto;
  # }

  /* Vary header manipulation */
  # Empty in simple configs.
  # By example, if we are storing & serving diferent objects depending on User-Agent header we must set the correct Vary header:
  # if (resp.http.Vary) {
  #   set resp.http.Vary = resp.http.Vary + ",User-Agent";
  # } else {
  #   set resp.http.Vary = "User-Agent";
  # }

  /* Fake headers */
  # Empty in simple configs
  # We can fake server headers here, by example:
  # set resp.http.Server = "Deep thought";
  # set resp.http.X-Powered-By = "BOFH";
  # Or have some fun with headers:
  # See http://www.nextthing.org/archives/2005/08/07/fun-with-http-headers
  # See http://royal.pingdom.com/2012/08/15/fun-and-unusual-http-response-headers/
  # set resp.http.X-Thank-You = "for bothering to look at my HTTP headers";
  # set resp.http.X-Answer = "42";

  /* Continue with built-in logic */
  # We want built-in logic to be processed after ours so we don't call return.
}
# sub vcl_deliver {
#     return (deliver);
# }

# vcl_error: Called when we hit an error, either explicitly or implicitly due to backend or internal errors.
sub vcl_error {
  /* Avoid DOS vulnerability CVE-2013-4484 */
  # See https://www.varnish-cache.org/lists/pipermail/varnish-announce/2013-October/000686.html
  if (obj.status == 400 || obj.status == 413) {
    return(deliver);
  }

  /* Do some Varnish black magic such as custom client redirections */
  # Empty in simple configs.
  # call perm_redirections_error;

  /* Try to restart request in case of failure */
  # Note that max_restarts defaults to 4
  # See https://www.varnish-cache.org/trac/wiki/VCLExampleRestarts
  if (obj.status == 503 && req.restarts < 4) {
    set obj.http.X-Restarts = req.restarts;
    return(restart);
  }

  /* Set common headers for synthetic responses */
  set obj.http.Content-Type = "text/html; charset=utf-8";

  /* HTTP Authentification client request */
  # Empty in simple configs. See http://blog.tenya.me/blog/2011/12/14/varnish-http-authentication/

  /* We're using error 200 for monitoring puposes */
  # Consider adding some analytics stuff to trace accesses
  if (obj.status == 200) {
    synthetic {"
      <?xml version="1.0" encoding="utf-8"?>
      <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
      "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
      <html>
        <head>
          <title>"} + obj.status + " " + obj.response + {"</title>
      </head>
      <body><h1>"} + obj.status + ": " + obj.response + {"</h1></body>
    "};
    return(deliver);
  }

  /* Error page & refresh / redirections */
  # We have plenty of choices when we have to serve an error to the client, 
  # from the default error page to javascript black magic or plain redirections.
  # Adding some external statistic javascript to track failures served to clients is strongly suggested.
  # We can't use external resources on synthetic content, everything must be inlined.
  # If we need to include images we can embed them in base64 encoding.
  # Here is the default error page for Varnish 3 (not so pretty)
  set obj.http.Retry-After = "5";
  synthetic {"
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html>
  <head>
    <title>"} + obj.status + " " + obj.response + {"</title>
  </head>
  <body>
    <h1>Error "} + obj.status + " " + obj.response + {"</h1>
    <p>"} + obj.response + {"</p>
    <h3>Guru Meditation:</h3>
    <p>XID: "} + req.xid + {"</p>
    <hr>
    <hr>
    <p>Varnish cache server</p>
  </body>
</html>
"};

  /* Bypass built-in logic */
  # We make sure no built-in logic is processed after ours returning at this point.
  return (deliver);
}

# vcl_init: Called when VCL is loaded, before any requests pass through it. Typically used to initialize VMODs.
# sub vcl_init {
#       return (ok);
# }

# vcl_fini: Called when VCL is discarded only after all requests have exited the VCL. Typically used to clean up VMODs.
# sub vcl_fini {
#       return (ok);
# }
