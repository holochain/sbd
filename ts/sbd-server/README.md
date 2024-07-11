# Cloudflare SbdServer

## Metrics

It's hard to get a sense of what is going on with distributed durable objects. To mitigate this, we are writing metrics to a KV called `SBD_COORDINATION`. These metrics can be enumerated from a central metrics http endpoint. However, as these metrics list IP addresses, and cause billable load on our worker kv endpoint, they will be guarded by an api key.

### Set Api Key

Set these api keys via worker secrets in the form: `METRIC_API_$(whoami)="$(uuidgen)"`.

E.g. `METRIC_API_NEONPHOG=d6d38e16-9fe2-4cbf-b66d-e49775064d59`

If doing this through the cloudflare dashboard, don't forget to click `encrypt`!

Or you can use `wrangler secret put METRIC_API_NEONPHOG` and then paste in the uuidgen result.

### Access the Metrics Endpoint

`$(url)/metris/$(whoami)/$(uuidgen)`

E.g. `https://sbd.holo.host/metrics/NEONPHOG/d6d38e16-9fe2-4cbf-b66d-e49775064d59`

Should give you something like:

```
# HELP client.count active client count
# TYPE client.count guage
client.count 4

# HELP client.recv.byte.count bytes received from client
# TYPE client.recv.byte.count guage
client.recv.byte.count{name="AqpAUD6QBb8lOfSBGna4C3tGAbI7E5slQ0MKkjm28kQ",opened=1720728911,active=1720728911,ip="no-ip"} 96

# HELP client.recv.byte.count bytes received from client
# TYPE client.recv.byte.count guage
client.recv.byte.count{name="R2qUfRVFfBhGGyxC4i_MorG48Ptk3JXwWvkIsh9mtRo",opened=1720728935,active=1720728935,ip="no-ip"} 96

# HELP client.recv.byte.count bytes received from client
# TYPE client.recv.byte.count guage
client.recv.byte.count{name="ia6EqgbobPhVrOdqlqZtL7v8EK5uDj5vlV4uTMB6vsY",opened=1720728936,active=1720728936,ip="no-ip"} 96

# HELP client.recv.byte.count bytes received from client
# TYPE client.recv.byte.count guage
client.recv.byte.count{name="u-JEHfSU6hArnHSjf9KA5W_ABH37go3Cm453UagScI8",opened=1720728911,active=1720728911,ip="no-ip"} 96
```
