# Simple DHCP for IPMI

This repo contains a tiny DHCP server you can run on your laptop to hand out an IP
to an IPMI management port connected via Ethernet. Tiny = VERY SIMPLE

## Setup

1) Assign a static IP to your laptop Ethernet adapter matching `server_ip`
   (default: `192.168.1.1 / 255.255.255.0` - no gateway or nameservers needed). 
2) Plug the IPMI port into the laptop's Ethernet.
3) Run the server as Administrator (required to bind UDP port 67).

## Run

```powershell
python dhcp_app.py --config config.json
```

## Configure

Edit `config.json`:

- `bind_ip`: IP to bind to (use `0.0.0.0` to listen on all interfaces)
- `server_ip`: your laptop's Ethernet IP
- `pool_start` / `pool_end`: IP range to hand out to the IPMI device
- `subnet_mask`, `router`, `dns`: basic network options
- `lease_time_seconds`: DHCP lease length

## Notes

- This is intentionally minimal and intended for a single device.
- If you need multiple leases or advanced options, use a full DHCP server.

