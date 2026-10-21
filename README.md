# SUB — merged subscription

One subscription built automatically from the public sources in `sources.txt`.

## Use it

Plain list (same format as before):
https://raw.githubusercontent.com/Ashollii/SUB/main/SUB.txt

Base64 version:
https://raw.githubusercontent.com/Ashollii/SUB/main/SUB.b64.txt

Paste either link as a subscription in v2rayNG / MahsaNG / similar apps.

## How it updates

GitHub Actions runs `merge.py` every 6 hours (and whenever `sources.txt`
changes): it fetches every source, decodes base64 payloads, extracts
configs, drops dummy 127.0.0.1 / 0.0.0.0 info entries, removes duplicates,
renames every config to `ASHKAN-1 <flag>`, `ASHKAN-2 <flag>`, ... — the flag is the country taken from the config's original name when it states one (otherwise 🌐) — including the `ps` name inside vmess configs,
and commits fresh `SUB.txt` / `SUB.b64.txt` files. IPv6-variant configs are dropped: they do not work on typical Iranian ISPs.

## Add or remove a source

Edit `sources.txt` — one URL per line — here on GitHub, or just ask Muse
in chat to add/remove a link. The next run rebuilds the merged file.
