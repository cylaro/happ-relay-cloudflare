# hwid-relay

[![Tests](https://github.com/cylaro/hwid-relay/actions/workflows/test.yml/badge.svg)](https://github.com/cylaro/hwid-relay/actions/workflows/test.yml)
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cylaro/hwid-relay)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

**Connect as many devices as you want to a panel with a HWID device limit — they all count as one device.**

A self-hosted relay on Cloudflare Workers (free plan). Your apps subscribe to the relay; the relay downloads the real subscription with one fixed device identity. The panel sees a single device — no matter how many phones, PCs or TVs you connect. Works with stock apps: Happ, v2RayTun, Streisand, Karing, FlClashX, and anything else that loads a subscription by URL.

[Инструкция на русском](README.ru.md)

---

## How it works (30 seconds)

Panels like [Remnawave](https://docs.rw/features/hwid-device-limit) count unique `x-hwid` header values per user. Every app generates its own value and cannot change it — so ten apps become ten devices.

The relay changes where your apps connect:

```
Phone 1 (Happ) ─┐
Phone 2 (Happ) ─┤   https://your-worker.workers.dev/<secret>/s/<token>
Phone 10     ─┘              │
                             ▼   fixed identity: ONE x-hwid, ONE User-Agent
                    Your Cloudflare Worker
                             │
                             ▼
                  Panel  ──>  sees exactly ONE device
```

---

## Step-by-step guide

### Before you start

You need:

1. **Your current subscription link** — the panel URL with your personal token, for example:
   `https://panel-provider.com/sub/6f9a2b1c-4e7d-4c1a-9b2e-8f5d3a7c1e2f`
   If you only have an encrypted `happ://crypt5/...` link, decrypt it first with [happ-decryptor](https://github.com/cylaro/happ-decryptor).
2. **A free Cloudflare account** — [dash.cloudflare.com](https://dash.cloudflare.com) → Sign up. No card required.
3. **5 minutes.**

### Step 1 — Deploy the worker

1. Press the **Deploy to Cloudflare** button above (or create a Worker manually: dash.cloudflare.com → **Workers & Pages** → **Create** → **Create Worker**).
2. Name it, for example `hwid-relay`, and finish the deployment.

You now have a worker at `https://hwid-relay.<your-subdomain>.workers.dev`.

### Step 2 — Build your device link

The device link is the worker URL + your secret + the **full panel URL**:

```
https://your-worker.workers.dev/<secret>/s/https://panel-provider.com/sub/6f9a2b1c-4e7d-4c1a-9b2e-8f5d3a7c1e2f
                                └────────────── secret ──────────────┘ └──────────────── panel URL ────────────────┘
```

Swap the panel URL for any other panel — the relay fetches it with your fixed identity. Hosts can be restricted with the `ALLOWED_HOSTS` variable if you plan to share the link.

### Step 3 — Choose the device identity

These values are what the panel will see as "the device":

| Field | Rule | Example |
|---|---|---|
| `HWID` | 10–64 chars: `A-Z a-z 0-9 = -` | `UE42LJXu4DbiCaBv` |
| `USER_AGENT` | any string, ideally matching a real client | `Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)` |
| `DEVICE_OS` | `iOS`, `Android`, `Windows`, `macOS`… | `iOS` |
| `VER_OS` | OS version | `18.3` |
| `DEVICE_MODEL` | device name | `iPhone 14 Pro` |

You can generate a random valid HWID with the [happ-decryptor](https://github.com/cylaro/happ-decryptor) editor (`+ HWID` button). Once chosen, keep these values **the same forever** — the panel remembers the device by them.

### Step 4 — Set the worker variables

In the Cloudflare dashboard:

1. **Workers & Pages** → `hwid-relay` → **Settings** → **Variables and Secrets**.
2. Add each variable below with type **Text**, pressing **Deploy** at the end:

| Name | Value |
|---|---|
| `HWID` | `UE42LJXu4DbiCaBv` |
| `USER_AGENT` | `Happ/1.16.0 (iOS 18.3; iPhone 14 Pro)` |
| `SECRET_PREFIX` | a random word, e.g. `hX7kQ2mV` |
| `DEVICE_OS` | `iOS` |
| `VER_OS` | `18.3` |
| `DEVICE_MODEL` | `iPhone 14 Pro` |

Saving variables redeploys the worker automatically.

### Step 5 — Health check

Open:

```
https://hwid-relay.<your-subdomain>.workers.dev/hX7kQ2mV/health
```

Expected answer:

```json
{"status":"ok","hint":"subscription URL: <worker>/SECRET_PREFIX/s/<token>"}
```

If you get `{"status":"misconfigured",...}` — the response lists exactly which variables are missing or invalid.

### Step 6 — Check that the panel accepts your identity

Open in any browser:

```
https://hwid-relay.<your-subdomain>.workers.dev/hX7kQ2mV/s/6f9a2b1c-4e7d-4c1a-9b2e-8f5d3a7c1e2f
```

You should see the subscription content (a text list of `vless://...` lines, Base64, or similar). This proves the panel accepted your HWID — the relay always sends exactly these headers.

Also check the panel user card (your provider's website or mini-app): the device list should now show **one device** with your `DEVICE_MODEL`.

Alternative check: [happ-decryptor](https://github.com/cylaro/happ-decryptor) → Request tab → send the panel URL with the same values and inspect the response headers.

### Step 7 — Connect your devices

In each app (Happ, v2RayTun, ...): add a subscription by URL:

```
https://hwid-relay.<your-subdomain>.workers.dev/hX7kQ2mV/s/6f9a2b1c-4e7d-4c1a-9b2e-8f5d3a7c1e2f
```

That's it. Update the subscription on every device — the panel still shows one device. Traffic quota display works too (`subscription-userinfo` is forwarded).

> **Do not share the relay link publicly** — anyone with it uses your traffic under your identity.

### Maintenance

| Event | Action |
|---|---|
| Provider issued a new token | Add the new device link with the new token |
| Provider moved the panel | Update `PANEL_BASE`, devices untouched |
| Want a different identity | Change `HWID`/`USER_AGENT`, then update the subscription on all devices |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/health` returns `{"status":"misconfigured","missing":[...]}` | A variable is missing or invalid | Fix the listed variable in Step 4 |
| Subscription opens, but `x-hwid-max-devices-reached: true` in response headers | The limit is already used by earlier devices | Delete old devices in the panel user card, or ask the owner to raise the limit |
| Panel returns 404 or empty body | Wrong token, the provider blocks Cloudflare IPs, or the panel requires an identity you did not configure | Open the original panel URL in a browser; if it works there, re-check your variables; if the provider blocks datacenter IPs, a relay on Cloudflare cannot help |
| `Not Found` from the worker | Wrong path or wrong `SECRET_PREFIX` | Use exactly `<worker>/<SECRET_PREFIX>/s/<token>` |
| Apps show no traffic quota | Panel does not send `subscription-userinfo` | Panel-side; not a relay issue |

## Honest limitations

- The panel sees one device whose requests come from Cloudflare IP ranges at a high frequency. A provider can notice this in server logs; using it against your plan's terms is your decision.
- If the provider blocks datacenter IPs, this relay cannot help — no free public service can fix that.
- One worker = one panel + one identity. Several panels → deploy the worker several times (or use full panel URLs in the links — hosts can be restricted with `ALLOWED_HOSTS`).
- Responses over 2 MiB (by Content-Length) are rejected; upstream requests time out after 15 seconds.

## Development

```bash
npm test            # unit tests: routing, headers, response filtering
npx wrangler dev    # run the worker locally
```

## Disclaimer

This project is provided for **educational purposes** — it demonstrates how HWID device counting works. You are solely responsible for how you use it: comply with your provider's terms of service and applicable law. The author is not affiliated with Happ, Remnawave or any provider, does not encourage violating any agreement, and accepts no liability for consequences of use. The software comes with no warranty (see [MIT license](LICENSE)).

## Related projects

- [happ-decryptor](https://github.com/cylaro/happ-decryptor) — decrypt `happ://crypt…` links, edit subscription URLs, send requests with device headers.
- [happ-relay-vercel](https://github.com/cylaro/happ-relay-vercel) — the same one-HWID relay on Vercel, with a serverless function instead of a Worker.

## License

[MIT](LICENSE)
