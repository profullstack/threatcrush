# Telling ThreatCrush which site was hit

nginx's stock `combined` log format does not record the vhost:

```
45.33.22.11 - - [25/Sep/2026:09:19:29 +0000] "GET /ring/dnin/previous HTTP/1.1" 402 614 "-" "Mozilla/5.0"
```

Every site on the box writes lines like that into the same file, so on a host
serving more than one site the log cannot say where a request landed — and
neither can ThreatCrush. The dashboard shows the path and the source address,
because that is all nginx wrote down.

Add `$host` to the front of the format and the site comes back:

```nginx
# /etc/nginx/nginx.conf, inside http { }
log_format vhost '$host $remote_addr - $remote_user [$time_local] '
                 '"$request" $status $body_bytes_sent '
                 '"$http_referer" "$http_user_agent"';

access_log /var/log/nginx/access.log vhost;
```

Then:

```sh
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak-001
sudo nginx -t && sudo systemctl reload nginx
```

ThreatCrush's parser accepts both formats, so nothing breaks while you roll this
out and nothing needs restarting on our side — new lines simply start carrying
the site, and it appears on the event.

## The alternative: a log per site

If you would rather not touch the shared format, give each server block its own
file:

```nginx
server {
    server_name rssamplifier.com;
    access_log /var/log/nginx/rssamplifier.access.log;
}
```

Add the path to `[modules.log-watcher] paths` so the watcher tails it. This is
the better choice when sites have very different traffic volumes, since it also
keeps one busy site from burying another in the same file.
