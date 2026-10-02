#!/usr/bin/env python3
import base64, json, re, socket, time, urllib.parse, urllib.request
from collections import defaultdict

SOURCES = [
    ("tested", "https://735754647.github.io/Free-Nodes/v2ray-raw.txt"),
    ("tested", "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/base64.txt"),
    ("fallback", "https://raw.githubusercontent.com/kooker/FreeSubsCheck/main/kooker.jp.txt"),
]
REGIONS = {
    "HK": ["香港", "Hong Kong", "HongKong", "🇭🇰"],
    "TW": ["台湾", "台灣", "Taiwan", "🇹🇼"],
    "KR": ["韩国", "韓國", "Korea", "South Korea", "🇰🇷"],
    "SG": ["新加坡", "Singapore", "狮城", "🇸🇬"],
    "US": ["美国", "美國", "United States", "USA", "🇺🇸"],
    "JP": ["日本", "Japan", "东京", "東京", "大阪", "🇯🇵"],
}
QUOTAS = {"HK": 9, "TW": 5, "KR": 6, "SG": 8, "US": 12, "JP": 10}
ALLOWED = ("ss://", "vmess://", "vless://", "trojan://")

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "runrab-shadowrocket-builder/1.0"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return r.read().decode("utf-8", "ignore").strip()

def b64decode_loose(s):
    s = s.strip()
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode("utf-8", "ignore")

def decode_subscription(text):
    if "://" in text:
        return text
    try:
        d = b64decode_loose(text)
        return d if "://" in d else text
    except Exception:
        return text

def display_name(uri):
    if uri.startswith("vmess://"):
        try:
            obj=json.loads(b64decode_loose(uri[8:].split("#",1)[0]))
            return str(obj.get("ps",""))
        except Exception:
            return ""
    if "#" in uri:
        return urllib.parse.unquote(uri.rsplit("#",1)[1])
    return ""

def region_of(name):
    low=name.lower()
    for reg, keys in REGIONS.items():
        if any(k.lower() in low for k in keys):
            return reg
    return None

def endpoint(uri):
    try:
        if uri.startswith("vmess://"):
            obj=json.loads(b64decode_loose(uri[8:].split("#",1)[0]))
            return obj.get("add"), int(obj.get("port"))
        p=urllib.parse.urlsplit(uri)
        return p.hostname, int(p.port)
    except Exception:
        return None, None

def compatible(uri):
    if not uri.startswith(ALLOWED):
        return False
    u=uri.lower()
    bad=("security=reality","type=xhttp","type=grpc","flow=xtls-rprx-vision","packetencoding=xudp")
    if any(x in u for x in bad):
        return False
    if uri.startswith("vmess://"):
        try:
            obj=json.loads(b64decode_loose(uri[8:].split("#",1)[0]))
            if str(obj.get("net","")).lower() in ("grpc","httpupgrade"):
                return False
        except Exception:
            return False
    host,port=endpoint(uri)
    return bool(host and port and 0 < port < 65536)

def key(uri):
    host,port=endpoint(uri)
    return (uri.split("://",1)[0],host,port,uri.split("#",1)[0])

def tcp_test(host,port,attempts=3):
    ok=0
    for i in range(attempts):
        try:
            with socket.create_connection((host,port), timeout=4):
                ok += 1
        except Exception:
            pass
        if i+1 < attempts:
            time.sleep(0.6)
    return ok

def rename(uri, label):
    enc=urllib.parse.quote(label, safe="")
    if uri.startswith("vmess://"):
        try:
            raw=uri[8:].split("#",1)[0]
            obj=json.loads(b64decode_loose(raw))
            obj["ps"]=label
            data=json.dumps(obj,ensure_ascii=False,separators=(",",":")).encode()
            return "vmess://"+base64.b64encode(data).decode()
        except Exception:
            return uri
    base=uri.split("#",1)[0]
    return base+"#"+enc

def main():
    candidates=[]
    seen=set()
    for priority,url in SOURCES:
        try:
            text=decode_subscription(fetch(url))
        except Exception as e:
            print("source failed",url,e)
            continue
        for line in text.splitlines():
            uri=line.strip()
            if not compatible(uri):
                continue
            name=display_name(uri)
            reg=region_of(name)
            if not reg:
                continue
            k=key(uri)
            if k in seen: continue
            seen.add(k)
            host,port=endpoint(uri)
            candidates.append({"uri":uri,"name":name,"region":reg,"host":host,"port":port,"priority":0 if priority=="tested" else 1})

    # Tested-source entries first, then fallback. Require >=2/3 TCP checks.
    candidates.sort(key=lambda x:(x["priority"], x["region"], x["name"]))
    passed=[]
    for i,c in enumerate(candidates):
        score=tcp_test(c["host"],c["port"],3)
        print(f'{i+1}/{len(candidates)} {c["region"]} {c["host"]}:{c["port"]} tcp={score}/3')
        if score >= 2:
            c["tcp_score"]=score
            passed.append(c)
        if len(passed) >= 120:
            break

    buckets=defaultdict(list)
    for c in passed:
        buckets[c["region"]].append(c)

    selected=[]
    # Fill quotas first.
    for reg in ("HK","TW","KR","SG","JP","US"):
        selected.extend(buckets[reg][:QUOTAS[reg]])
        buckets[reg]=buckets[reg][QUOTAS[reg]:]
    # Fill remaining up to 50, round-robin.
    order=("SG","JP","HK","TW","KR","US")
    while len(selected)<50:
        progressed=False
        for reg in order:
            if buckets[reg] and len(selected)<50:
                selected.append(buckets[reg].pop(0)); progressed=True
        if not progressed: break

    counts=defaultdict(int)
    lines=[]
    for c in selected:
        counts[c["region"]]+=1
        label=f'{c["region"]}-{counts[c["region"]]:02d} ✓{c["tcp_score"]}/3'
        lines.append(rename(c["uri"],label))

    raw="\n".join(lines)+"\n"
    encoded=base64.b64encode(raw.encode()).decode()
    import pathlib
    out=pathlib.Path("shadowrocket")
    out.mkdir(exist_ok=True)
    (out/"px-raw.txt").write_text(raw,encoding="utf-8")
    (out/"px.txt").write_text(encoded+"\n",encoding="utf-8")
    report={
        "generated_at":time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime()),
        "total":len(selected),
        "regions":dict(counts),
        "criteria":"Shadowrocket-compatible URI; primary tested upstream; TCP 3 attempts and require >=2 successes",
        "warning":"TCP success is not a complete end-to-end proxy handshake; primary source is prioritized because it performs Mihomo proxy connectivity tests."
    }
    (out/"report.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False))

if __name__=="__main__":
    main()
