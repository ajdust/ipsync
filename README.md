# ipsync

Perform an action on Server A when the IP address of Server B changes. Use CRON or another scheduler to hit the `/ping` endpoint every few seconds. When the endpoint detects that the IP changed, run a script. For instance, update an Envoy configuration containing an IP address, and restart Envoy.

