# Networking: getting files in and the history page out

drop-vet needs two network paths, and neither has to be Tailscale:

1. **Mac → server over SSH.** The app runs plain `ssh` and `scp` against the host alias you set in
   `defaults write dev.drop-vet.app SSHHost <alias>`. Anything that lets your Mac reach the
   server's SSH port works.
2. **You → history page.** `drop-vet serve` listens on `127.0.0.1:8750` only, on purpose, because it
   has no login of its own. To see it from another machine, put something in front of it that
   controls who gets in.

Pick one row:

| Setup | Upload path | History page | Effort | Reach from outside home |
|---|---|---|---|---|
| [A. Tailscale](#a-tailscale-recommended) (recommended) | tailnet SSH | `tailscale serve` | low | yes |
| [B. Same home network](#b-same-home-network-only) | LAN SSH | SSH tunnel | lowest | no |
| [C. Your own VPN (WireGuard)](#c-your-own-vpn-wireguard) | VPN SSH | SSH tunnel, or bind to the VPN address | medium | yes |
| [D. SSH open to the internet](#d-ssh-open-to-the-internet) | public SSH | SSH tunnel, or a proxy with a login | medium, needs care | yes |

Whichever you pick, the uploads travel inside SSH and are encrypted. The setups differ in who can
*reach* the server and the page.

## A. Tailscale (recommended)

Tailscale gives every device a private, encrypted address and a stable name. Nothing is opened to
the internet, and it works the same at home and away.

1. **Install it on the server and the Mac:** [tailscale.com/download](https://tailscale.com/download),
   then sign both in to the same tailnet.
2. **Turn on MagicDNS** so you can use names instead of `100.x` addresses:
   [MagicDNS](https://tailscale.com/docs/features/magicdns).
3. **Point the app at the server.** In `~/.ssh/config` on the Mac:
   ```
   Host myserver
       HostName myserver
       User you
   ```
   With MagicDNS on, the server's short machine name resolves on every device in the tailnet. Then
   run `defaults write dev.drop-vet.app SSHHost myserver`.
4. **Publish the history page to your tailnet only** with
   [Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve). Serve needs HTTPS
   certificates turned on for your tailnet:
   [set up HTTPS certificates](https://tailscale.com/docs/how-to/set-up-https-certificates).
   ```sh
   sudo tailscale serve --bg 8750
   ```
   `tailscale serve status` prints the HTTPS URL (the server's full MagicDNS name). Set it with
   `defaults write dev.drop-vet.app HistoryURL <that URL>`. Serve is
   tailnet-only. Do **not** use Funnel, which publishes to the whole internet.
5. **Limit who can reach the server** (strongly recommended). By default every device in a tailnet
   can reach every other. The history page has no login, so restrict it with
   [grants](https://tailscale.com/docs/features/access-control/grants) (or the older
   [ACLs](https://tailscale.com/docs/features/access-control/acls)). A sketch that lets only your
   laptop and phone reach the server's SSH and HTTPS:
   ```json
   {
     "tagOwners": { "tag:dropvet-server": ["autogroup:admin"] },
     "grants": [
       {
         "src": ["you@example.com"],
         "dst": ["tag:dropvet-server"],
         "ip": ["tcp:22", "tcp:443"]
       }
     ]
   }
   ```
   Tag the server with `sudo tailscale up --advertise-tags=tag:dropvet-server`. Narrow `src` further
   (specific devices or a group) if shared or low-trust devices such as e-readers and game consoles
   sit on the same tailnet.
6. **Optional hardening:**
   - [Tailnet Lock](https://tailscale.com/docs/features/tailnet-lock) makes new devices need a
     signature from one you trust before they can join.
   - [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh) can replace SSH keys with
     tailnet identity. The app works either way, because it just runs `ssh`.
   - If the server also acts as a [subnet router](https://tailscale.com/docs/features/subnet-routers),
     grants apply to that route too. Don't hand your whole home network to every device.

## B. Same home network only

The simplest setup, if you only drop files while at home.

1. Give the server a fixed address (a DHCP reservation in your router) or use its `.local` name.
2. In `~/.ssh/config` on the Mac:
   ```
   Host myserver
       HostName myserver.local
       User you
   ```
3. History page through an SSH tunnel. Run this on the Mac, leave it open, then browse to
   `http://127.0.0.1:8750/`:
   ```sh
   ssh -N -L 8750:127.0.0.1:8750 myserver
   ```
   ([`ssh -L` reference](https://man.openbsd.org/ssh)). The `HistoryURL` setting can point at
   `http://127.0.0.1:8750/` while the tunnel is up.

Anyone on your Wi-Fi can try to reach the server's SSH port, so use key-only login (see D, step 1).

## C. Your own VPN (WireGuard)

The same idea as Tailscale, set up by hand. You run the VPN endpoint, usually the server or your
router, and open one UDP port.

1. Follow the [WireGuard quick start](https://www.wireguard.com/quickstart/) to give the server and
   the Mac VPN addresses.
2. Use the server's VPN address as `HostName` in `~/.ssh/config`.
3. History page: either the SSH tunnel from B, or set `DROP_VET_HOST` to the server's **VPN
   address** (never `0.0.0.0`) and allow that port only on the VPN interface in your firewall
   ([Ubuntu firewall guide](https://documentation.ubuntu.com/server/how-to/security/firewalls/)).

## D. SSH open to the internet

This works, and it is how many people reach a home server, but the SSH port then gets scanned
constantly. Only do this with the hardening below.

1. **Key-only SSH.** In `/etc/ssh/sshd_config`
   ([reference](https://man.openbsd.org/sshd_config)):
   ```
   PasswordAuthentication no
   KbdInteractiveAuthentication no
   PermitRootLogin no
   ```
   Then `sudo systemctl reload ssh`. Make sure your key login works first, from a second terminal.
2. **Rate-limit attackers** with [fail2ban](https://github.com/fail2ban/fail2ban).
3. **Forward only the SSH port** on your router, never 8750.
4. **History page:** the SSH tunnel from B. If you want a plain URL instead, put it behind a proxy
   that requires a login:
   - [Caddy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy) with
     [`basic_auth`](https://caddyserver.com/docs/caddyfile/directives/basic_auth):
     ```
     drop.example.com {
         basic_auth {
             you <bcrypt hash from `caddy hash-password`>
         }
         reverse_proxy 127.0.0.1:8750
     }
     ```
   - Or [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/)
     plus a [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/self-hosted-public-app/)
     policy, which opens no inbound port at all.

## Restricting the Mac's SSH key (any setup)

The app uses whatever key your SSH alias offers. If that is your everyday login key, a compromised
laptop has a full shell on the server. To limit the damage, give drop-vet its own key
(`IdentityFile` in the alias) and, on the server, put `restrict` plus a forced command on that key in
`~/.ssh/authorized_keys` that allows only what the app runs: `mkdir` and `mv` under
`landing/`, and `scp` uploads into `landing/.part-*`. See `AUTHORIZED_KEYS FILE FORMAT` in
[sshd(8)](https://man.openbsd.org/sshd.8). A ready-made wrapper is planned and not yet included.

## Which one should I use?

- You already use Tailscale, or you want it to work away from home with no open ports: **A**.
- Home only, no new software: **B**.
- You run your own VPN already: **C**.
- You can't install anything on the Mac but can forward a port: **D**, with all of its hardening.
