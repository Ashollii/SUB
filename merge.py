#!/usr/bin/env python3
"""Merge multiple v2ray subscription sources into one deduplicated list.
Usage: merge.py sources.txt merged_plain.txt [merged_b64.txt]
- A source can be: an http(s) URL (fetched), or a local file path.
- Content may be base64-encoded (whole payload), plain lines, or a mix.
- Extracts URI configs, dedupes by config identity ignoring the #name fragment,
  keeps the first occurrence's original line.
"""
import sys, base64, urllib.request, urllib.parse, re

PROTOCOLS = ("vmess://","vless://","trojan://","ss://","ssr://","hysteria://","hysteria2://","hy2://","tuic://","wireguard://","socks://","http://","https://")
# note: http(s) only counted when it looks like a proxy URI in a line by itself is rare; keep them out unless ss-style
URI_RE = re.compile(r'(vmess|vless|trojan|ss|ssr|hysteria2|hysteria|hy2|tuic|wireguard|socks|socks5)://[^\s\'"<>]+')

def maybe_b64_decode(text: str) -> str:
    t = re.sub(r'\s+', '', text)
    if len(t) >= 40 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', t or ''):
        try:
            padded = t + '=' * (-len(t) % 4)
            dec = base64.b64decode(padded, altchars=b'-_').decode('utf-8', 'ignore')
            if '://' in dec:
                return dec
        except Exception:
            pass
    return text

def _fetch_full(url: str, timeout: int = 30) -> bytes:
    """Read a whole response body, resuming with HTTP Range requests
    whenever the egress proxy truncates it mid-body. A plain read()
    raises IncompleteRead in that case and used to zero out the whole
    source (the sub bot then reported 0 configs)."""
    import http.client, time as _time
    buf = b""
    total = None
    last_err = None
    for _ in range(12):
        headers = {'User-Agent': 'Mozilla/5.0 sub-merger'}
        if buf:
            headers['Range'] = f'bytes={len(buf)}-'
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                status = getattr(r, 'status', 200)
                cr = r.headers.get('Content-Range') or ''
                if '/' in cr:
                    try:
                        total = int(cr.rsplit('/', 1)[1])
                    except ValueError:
                        pass
                elif r.headers.get('Content-Length'):
                    total = int(r.headers['Content-Length']) + (len(buf) if status == 206 else 0)
                data = r.read()
                buf = buf + data if (buf and status == 206) else data
        except http.client.IncompleteRead as e:
            part = e.partial or b''
            buf = buf + part if buf else part
            if e.expected is not None:
                total = len(buf) + e.expected
        except Exception as e:
            last_err = e
            _time.sleep(1.0)
        if total is not None and len(buf) >= total:
            break
        _time.sleep(0.3)
    if total is not None and len(buf) < total:
        raise IOError(f'incomplete fetch: {len(buf)}/{total} bytes')
    if not buf and last_err is not None:
        raise last_err
    return buf

def fetch(src: str) -> str:
    if src.startswith(('http://','https://')):
        return _fetch_full(src).decode('utf-8','ignore')
    with open(src, encoding='utf-8', errors='ignore') as f:
        return f.read()

def host_of(uri: str) -> str:
    proto = uri.split('://',1)[0]
    rest = uri.split('://',1)[1] if '://' in uri else ''
    if proto == 'vmess':
        import base64 as _b64, json as _json
        try:
            padded = rest.split('#',1)[0] + '=' * (-len(rest.split('#',1)[0]) % 4)
            return str(_json.loads(_b64.b64decode(padded)).get('add',''))
        except Exception:
            return ''
    # userinfo@host:port forms
    rest = rest.split('#',1)[0]
    if '@' in rest:
        rest = rest.rsplit('@',1)[1]
    rest = rest.split('?',1)[0].split('/',1)[0]
    if rest.startswith('['):
        return rest[1:].split(']',1)[0]
    return rest.rsplit(':',1)[0] if ':' in rest else rest

def is_dummy(uri: str) -> bool:
    host = host_of(uri)
    if host == '127.0.0.1':
        # Placeholder-address configs (EdgeOne/snip style) carry the real
        # endpoint in the host/sni params; Ashkan asked to let those in
        # (2026-10-23). A bare 127.0.0.1 with no override stays dummy.
        q = uri.split('?', 1)[1].split('#', 1)[0] if '?' in uri else ''
        return not ('host=' in q or 'sni=' in q)
    return host in ('0.0.0.0', 'localhost', '::1')

def ip_version(uri: str) -> str:
    """'IPv6' when the config's server address is a literal IPv6 address,
    else 'IPv4' (literal IPv4, or a domain name — domains in these lists
    are used over IPv4). Based on the address form, not DNS."""
    import ipaddress
    host = host_of(uri)
    try:
        return 'IPv6' if ipaddress.ip_address(host).version == 6 else 'IPv4'
    except ValueError:
        return 'IPv6' if ':' in host else 'IPv4'

def identity(uri: str) -> str:
    # dedupe key: everything before '#'
    return uri.split('#',1)[0].strip()

def stable_key(uri: str) -> str:
    """Name-insensitive identity of a config, stable across renames.

    identity() still contains the display name for vmess (inside the
    base64 payload's "ps") and ssr (the remarks param), so a config in
    the previously published SUB — where every entry carries an ASHKAN
    name — would never match the same config freshly read from a
    source. stable_key strips the name so the same config can be
    recognised under either name. Used for the blacklist.
    """
    import hashlib, json as _json
    proto = uri.split('://', 1)[0].lower() if '://' in uri else ''
    if proto == 'vmess':
        payload = uri.split('://', 1)[1].split('#', 1)[0]
        try:
            padded = payload + '=' * (-len(payload) % 4)
            obj = _json.loads(base64.b64decode(padded, altchars=b'-_'))
            obj.pop('ps', None)
            raw = _json.dumps(obj, sort_keys=True,
                              ensure_ascii=False).encode()
            return 'vmess:' + hashlib.sha1(raw).hexdigest()
        except Exception:
            return 'vmess:' + identity(uri)
    if proto == 'ssr':
        payload = uri.split('://', 1)[1].split('#', 1)[0]
        try:
            padded = payload + '=' * (-len(payload) % 4)
            decoded = base64.b64decode(padded, altchars=b'-_') \
                .decode('utf-8', 'ignore')
            main, _, query = decoded.partition('/?')
            kept = [p for p in (query.split('&') if query else [])
                    if p and not p.startswith('remarks=')]
            raw = (main + '/?' + '&'.join(kept)).encode()
            return 'ssr:' + hashlib.sha1(raw).hexdigest()
        except Exception:
            return 'ssr:' + identity(uri)
    return identity(uri)

def b64url_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip('=')

KNOWN_CC = {'US','GB','UK','DE','NL','FR','CA','IR','FI','SE','NO','DK','RU','HK','TR','AE','SG','JP','KR','IN','IT','ES','CH','AT','PL','UA','CZ','RO','BG','ME','SC','ES','BE','IE','LU','EE','LV','LT','GR','PT','HU','SK','SI','HR','RS','AL','KZ','UZ','AZ','GE','AM','IQ','SA','QA','OM','KW','BH','EG','ZA','NG','KE','BR','MX','AR','CL','CO','PE','AU','NZ','ID','MY','TH','VN','PH','TW','CN','PK','BD','LK','MM','KH'}
COUNTRY_NAMES = {'germany':'DE','netherlands':'NL','holland':'NL','france':'FR','canada':'CA','united states':'US','america':'US','usa':'US','united kingdom':'GB','england':'GB','uk':'GB','iran':'IR','finland':'FI','sweden':'SE','russia':'RU','hong kong':'HK','turkey':'TR','singapore':'SG','japan':'JP','korea':'KR','india':'IN','italy':'IT','spain':'ES','switzerland':'CH','austria':'AT','poland':'PL','ukraine':'UA','romania':'RO','bulgaria':'BG','montenegro':'ME','seychelles':'SC'}

def flag_of_code(cc: str) -> str:
    cc = 'GB' if cc == 'UK' else cc
    if len(cc) != 2 or not cc.isalpha():
        return ''
    return ''.join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())

def original_name(uri: str) -> str:
    proto = uri.split('://',1)[0].lower() if '://' in uri else ''
    if proto == 'vmess':
        payload = uri.split('://',1)[1].split('#',1)[0]
        try:
            import json as _json
            padded = payload + '=' * (-len(payload) % 4)
            return str(_json.loads(base64.b64decode(padded, altchars=b'-_')).get('ps',''))
        except Exception:
            return ''
    if '#' in uri:
        return urllib.parse.unquote(uri.split('#',1)[1])
    return ''

def extract_flag(name: str) -> str:
    if not name:
        return ''
    import re as _re
    m = _re.search(r'[\U0001F1E6-\U0001F1FF]{2}', name)
    if m:
        f = m.group(0)
        code = ''.join(chr(ord(c) - 0x1F1E6 + 65) for c in f)
        return f if code != 'XX' else ''
    low = ' ' + name.lower() + ' '
    for cname, cc in COUNTRY_NAMES.items():
        if _re.search(r'[^a-z]' + _re.escape(cname) + r'[^a-z]', low):
            return flag_of_code(cc)
    for tok in _re.findall(r'(?<![A-Za-z])[A-Z]{2}(?![A-Za-z])', name):
        if tok in KNOWN_CC:
            return flag_of_code(tok)
    return ''

def rename_uri(uri: str, name: str) -> str:
    proto = uri.split('://',1)[0].lower() if '://' in uri else ''
    if proto == 'vmess':
        payload = uri.split('://',1)[1].split('#',1)[0]
        try:
            padded = payload + '=' * (-len(payload) % 4)
            import json as _json
            obj = _json.loads(base64.b64decode(padded, altchars=b'-_'))
            obj['ps'] = name
            raw = _json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode()
            return 'vmess://' + base64.b64encode(raw).decode()
        except Exception:
            return uri.split('#',1)[0] + '#' + urllib.parse.quote(name, safe='')
    if proto == 'ssr':
        payload = uri.split('://',1)[1].split('#',1)[0]
        try:
            padded = payload + '=' * (-len(payload) % 4)
            decoded = base64.b64decode(padded, altchars=b'-_').decode('utf-8','ignore')
            main, _, query = decoded.partition('/?')
            params = []
            found = False
            for part in (query.split('&') if query else []):
                if part.startswith('remarks='):
                    params.append('remarks=' + b64url_nopad(name.encode())); found = True
                elif part:
                    params.append(part)
            if not found:
                params.append('remarks=' + b64url_nopad(name.encode()))
            rebuilt = main + '/?' + '&'.join(params)
            return 'ssr://' + b64url_nopad(rebuilt.encode())
        except Exception:
            return uri
    # fragment-named protocols: vless, trojan, ss, hysteria(2), tuic, wireguard, socks...
    base = uri.split('#',1)[0]
    return base + '#' + urllib.parse.quote(name, safe='')

# Subscription meta headers: comment lines many clients (v2rayNG, Streisand,
# NekoBox, Hiddify...) parse from the subscription body itself.
#   profile-title          -> subscription display name
#   profile-update-interval-> auto-update interval in hours
#   subscription-userinfo  -> usage display (0 = unlimited / no expiry)
#   support-url            -> support button (Telegram plane icon -> his chat)
#   profile-web-page-url   -> info (i) button -> the SUB repo page
# Added 2026-10-24 at Ashkan's request (Patterniha-style sub header).
SUB_HEADERS = [
    '#profile-title: ASHKAN',
    '#profile-update-interval: 1',
    '#subscription-userinfo: upload=0; download=0; total=0; expire=0',
    '#support-url: https://t.me/A5HKANI',
    '#profile-web-page-url: https://github.com/Ashollii/SUB',
]


def main():
    argv = sys.argv[1:]
    rename = None; numbered = False
    if '--rename' in argv:
        i = argv.index('--rename'); rename = argv[i+1]; del argv[i:i+2]
    if '--numbered' in argv:
        argv.remove('--numbered'); numbered = True
    drop_ipv6 = False
    if '--drop-ipv6-variant' in argv:
        argv.remove('--drop-ipv6-variant'); drop_ipv6 = True
    sources_file, out_plain = argv[0], argv[1]
    out_b64 = argv[2] if len(argv) > 2 else None
    sources = [l.strip() for l in open(sources_file) if l.strip() and not l.strip().startswith('#')]
    import os as _os
    # Optional permanent blacklist: one config per line in blacklist.txt
    # next to the sources file (matched name-insensitively). Absent
    # file = no-op. Entries are added by hand when the owner names a
    # dead config in chat — he never has to forward anything.
    blacklist = set()
    _bl = _os.path.join(_os.path.dirname(_os.path.abspath(sources_file)),
                        'blacklist.txt')
    if _os.path.exists(_bl):
        try:
            blacklist = {stable_key(l.strip())
                         for l in open(_bl, encoding='utf-8',
                                       errors='ignore')
                         if l.strip() and not l.strip().startswith('#')}
        except Exception:
            blacklist = set()
    seen, merged, report = set(), [], []
    src_of = {}
    for src in sources:
        try:
            raw = fetch(src)
        except Exception as e:
            report.append(f"FAIL {src} -> {e}")
            continue
        text = maybe_b64_decode(raw)
        found = URI_RE.findall(text) and URI_RE.findall(text) or []
        uris = [m.group(0) if hasattr(m,'group') else m for m in URI_RE.finditer(text)] if False else [mm.group(0) for mm in URI_RE.finditer(text)]
        new = 0
        for u in uris:
            u = u.strip().rstrip(',\'")')
            if is_dummy(u):
                continue
            if blacklist and stable_key(u) in blacklist:
                continue
            k = identity(u)
            if k and k not in seen:
                seen.add(k); merged.append(u); src_of[k] = src; new += 1
        report.append(f"OK   {src} -> {len(uris)} configs, {new} new")
    if drop_ipv6:
        before = len(merged)
        merged = [u for u in merged if not original_name(u).startswith('IPv6')]
        print(f"Dropped IPv6-variant configs: {before - len(merged)}")
    if rename:
        renamed = []
        for idx, u in enumerate(merged, 1):
            base = f"{rename}-{idx}" if numbered else rename
            fl = extract_flag(original_name(u)) or '\U0001F310'
            nm = f"{base} {fl} {ip_version(u)}"
            if 'fragment_fingerprint' in src_of.get(identity(u), ''):
                nm += ' F-F'
            renamed.append(rename_uri(u, nm))
        merged = renamed
    body = '\n'.join(SUB_HEADERS + merged)
    with open(out_plain,'w',encoding='utf-8') as f:
        f.write(body + ('\n' if merged else ''))
    if out_b64:
        with open(out_b64,'w',encoding='utf-8') as f:
            f.write(base64.b64encode(body.encode()).decode())
    print('\n'.join(report))
    print(f"TOTAL unique configs: {len(merged)}")

if __name__ == '__main__':
    main()
