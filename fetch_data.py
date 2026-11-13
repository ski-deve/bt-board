#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 두 파일을 만듭니다.
  site/data.json   : 보안뉴스 / CISA KEV / NVD / Cisco 권고 / 국내 보안행사 / 부산 날씨 / 통계
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)
"""
import email.utils
import html
import json
import os
import re
import time
import datetime as dt
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

# ----------------------------- 설정 -----------------------------
NEWS_FEEDS = [
    ("보안뉴스", "https://www.boannews.com/rss/allArticle.xml"),
    ("데일리시큐", "https://www.dailysecu.com/rss/allArticle.xml"),
    ("KISA", "https://knvd.krcert.or.kr/rss/securityNotice.do"),
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUSAN = (35.1796, 129.0756)
EVENTS_FILE = Path("events.json")

THREAT_MID = 5
THREAT_HIGH = 10

AUTO = {"news": 0, "kev": 0, "nvd": 0, "psirt": 0, "events": 0}

TARGET_SITES = [
    {"name": "부산정보산업진흥원_ICT교육", "label": "BIPA 교육", "url": "https://bipa.kr/board/training/list", "domain": "https://bipa.kr", "require_param": "seq=", "need_event": False},
    {"name": "부산정보산업진흥원_일반공고", "label": "BIPA 공고", "url": "https://bipa.kr/board/notice/list", "domain": "https://bipa.kr", "require_param": "seq=", "need_event": True},
    {"name": "부산경제진흥원_소상공인디지털", "label": "BEPA", "url": "https://www.bepa.kr/kor/view.do?no=1502", "domain": "https://www.bepa.kr", "require_param": "idx=", "need_event": True},
    {"name": "부산경제진흥원_기업지원사업", "label": "BEPA", "url": "https://www.bepa.kr/kor/view.do?no=1505", "domain": "https://www.bepa.kr", "require_param": "idx=", "need_event": True},
    {"name": "부산과학기술고등교육진흥원_사업", "label": "BISTEP", "url": "https://www.bistep.re.kr/board.es?mid=a10301010000&bid=0002", "domain": "https://www.bistep.re.kr", "require_param": "nttSn=", "need_event": True},
    {"name": "부산상공회의소_교육행사", "label": "부산상의", "url": "https://www.bcci.or.kr/", "domain": "https://www.bcci.or.kr", "require_param": "seq=", "need_event": True},
    {"name": "부산지방중소벤처기업청_공고", "label": "부산중기청", "url": "https://www.mss.go.kr/site/busan/ex/bbs/List.do?cbIdx=277", "domain": "https://www.mss.go.kr", "require_param": "seq=", "need_event": True},
]
BEXCO_URL = "https://www.bexco.co.kr/kor/CMS/EventScheduleMgr/list.do?mCode=MN214"

SEC_KW = ["보안", "정보보호", "사이버", "해킹", "개인정보", "랜섬", "침해", "암호", "제로트러스트", "zero trust", "시큐리티", "security", "isms", "ciso", "망분리", "취약점", "포렌식", "위협", "방화벽"]
EXCLUDE_WORDS = ["입찰", "채용", "낙찰", "계약", "합격", "선정 결과", "결과 안내", "결과 공고", "용역"]
EVENT_WORDS = ["세미나", "교육", "컨퍼런스", "콘퍼런스", "워크숍", "웨비나", "설명회", "포럼", "아카데미", "해커톤", "강좌", "강연", "실습", "행사", "대회", "박람회", "전시"]
ACTION_WORDS = ["모집", "접수", "개최", "신청", "참가", "초청", "등록", "안내", "예정", "오픈"]
PAST_WORDS = ["성료", "마쳐", "마치", "성황", "폐막", "막내렸", "참가해", "참가했", "열렸", "진행했", "수료"]
EVENT_TYPES = [
    ("웨비나", ["웨비나", "온라인 강연"]),
    ("컨퍼런스", ["컨퍼런스", "콘퍼런스"]),
    ("교육", ["교육", "강좌", "아카데미", "실습", "훈련", "과정"]),
    ("세미나", ["세미나", "포럼", "설명회", "워크숍", "강연"]),
    ("전시", ["전시", "박람회", "엑스포"]),
]

USE_NEWS_SEARCH = False
EVENT_SEARCH = []

OUT = Path("site")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36", "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5"}
KST = dt.timezone(dt.timedelta(hours=9))

_KEV_CACHE = None
_NVD_TOTAL = None

def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def decode_html(raw):
    for enc in ("utf-8", "cp949"):
        try: return raw.decode(enc)
        except UnicodeDecodeError: continue
    return raw.decode("utf-8", "ignore")

def to_epoch(s):
    if not s: return 0
    s = s.strip()
    try: return int(email.utils.parsedate_to_datetime(s).timestamp())
    except Exception: pass
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None: d = d.replace(tzinfo=KST)
        return int(d.timestamp())
    except Exception: return 0

def clean(s):
    s = html.unescape(s or "")
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", s).strip()

def parse_rss(url, source):
    root = ET.fromstring(http_get(url))
    out = []
    for it in root.iter("item"):
        title = clean(it.findtext("title"))
        if not title: continue
        pub = it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")
        out.append({
            "src": source, "title": title,
            "link": (it.findtext("link") or "").strip(),
            "ts": to_epoch(pub),
            "desc": clean(it.findtext("description") or it.findtext("{http://www.w3.org/2005/Atom}summary") or "")[:400],
        })
    return out

ATTACKS = [
    (("remote code execution", "arbitrary code", "code execution", "command injection", "os command", "code injection", "deserialization"), "원격 코드 실행", "서버를 원격으로 장악", 1),
    (("authentication bypass", "improper authentication", "missing authentication", "authorization bypass", "default credential", "hard-coded", "hardcoded", "auth bypass"), "인증 우회", "로그인 없이 접근", 1),
    (("privilege escalation", "elevation of privilege", "improper privilege", "privilege"), "권한 상승", "관리자 권한 탈취", 1),
    (("sql injection",), "SQL 인젝션", "DB 정보 탈취·변조", 1),
    (("xml external entity", "xxe", "server-side request forgery", "ssrf"), "XXE·SSRF", "내부 정보 유출", 2),
    (("path traversal", "directory traversal", "file upload", "arbitrary file", "file read", "file inclusion"), "파일 조작·탈취", "서버 파일 열람·유출", 2),
    (("security feature bypass", "bypass"), "보안 기능 우회", "방어 장치 무력화", 2),
    (("buffer overflow", "use after free", "use-after-free", "out-of-bounds", "memory corruption", "heap", "type confusion"), "메모리 손상", "코드 실행·장애 유발", 2),
    (("denial of service", "denial-of-service", "resource exhaustion", "crash"), "서비스 거부(DoS)", "장비 중단·마비", 3),
    (("cross-site scripting", "xss"), "XSS", "악성 스크립트 실행", 3),
    (("information disclosure", "sensitive information", "information exposure", "information leak", "disclosure"), "정보 노출", "민감정보 유출", 3),
]
DEFAULT_ATK = ("기타 취약점", "상세 내용은 원문 확인", 3)

DEFAULT_CAT = "기타 SW·장비"
CATS = [
    (("vpn", "firewall", "adaptive security appliance", "asa", "ftd", "firepower", "fortios", "fortigate", "pan-os", "sonicwall", "globalprotect", "netscaler", "big-ip", "secure client"), "방화벽·VPN"),
    (("exchange", "mail", "webmail", "zimbra", "roundcube", "postfix", "esa"), "메일 서버"),
    (("chrome", "chromium", "firefox", "edge", "safari", "browser", "webkit"), "웹 브라우저"),
    (("windows", "kernel", "linux", "ubuntu", "android", "ios", "macos", "apple"), "OS·커널"),
    (("wordpress", "php", "apache", "nginx", "tomcat", "iis", "node.js", "openssh", "ssh", "web", "joomla", "drupal", "struts", "spring"), "웹·서버 SW"),
    (("sql", "oracle", "mysql", "postgres", "postgresql", "database", "mongodb", "redis"), "데이터베이스"),
    (("router", "switch", "meraki", "access point", "wlc", "camera", "nas", "synology", "qnap", "d-link", "dlink", "tp-link", "zyxel"), "네트워크·IoT 장비"),
    (("vmware", "esxi", "vcenter", "hyper-v", "citrix", "kubernetes", "docker", "gitlab", "jenkins", "ibm", "sap", "gpustack", "aspera"), "서버·플랫폼"),
]
SOL = {
    "방화벽·VPN": "AXGATE·Cisco FirePower",
    "메일 서버": "Cisco ESA",
    "웹·서버 SW": "SolidStep·MetiEye",
    "OS·커널": "지니언스 EDR",
    "웹 브라우저": "지니언스 EDR",
    "데이터베이스": "넷앤드 DB접근통제",
    "네트워크·IoT 장비": "지니언스 NAC·Meraki",
    "서버·플랫폼": "SolidStep·넷앤드 PSM",
    "Cisco 장비·SW": "Cisco 보안 패치",
    DEFAULT_CAT: "Ai-Spera CTI",
}
OUR_VENDORS = ("cisco", "genians", "axgate", "netand", "ai-spera", "ssr")
SEV_KO = {"Critical": "치명", "High": "높음", "Medium": "중간", "Low": "낮음"}

def classify(*texts):
    for t in texts:
        low = (t or "").lower()
        for keys, label, eff, lvl in ATTACKS:
            if any(k in low for k in keys): return label, eff, lvl
    return DEFAULT_ATK

def categorize(text):
    low = (text or "").lower()
    for keys, cat in CATS:
        if any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in keys): return cat
    return DEFAULT_CAT

def guess_product(desc):
    try:
        m = re.search(r"(?:vulnerability|flaw|issue|weakness) in (?:the )?(.{4,60}?)(?: (?:of|could|allows|that|which|before|prior|through|version)\b|[,.;(])", desc, re.I)
        if m: return m.group(1).strip()
        m = re.match(r"(.{4,40}?)(?: (?:before|prior to|through|version|allows|is|in|up to)\b|[,(])", desc)
        return (m.group(1) if m else desc[:40]).strip()
    except Exception: return desc[:40]

def kev_item(v):
    name = v.get("vulnerabilityName", "")
    vendor = v.get("vendorProject", "")
    product = v.get("product", "")
    short = v.get("shortDescription", "")
    atk, eff, lvl = classify(name, short)
    cat = categorize(" ".join([vendor, product, name, short]))
    if cat == DEFAULT_CAT and "cisco" in vendor.lower(): cat = "Cisco 장비·SW"
    return {
        "cve": v.get("cveID", ""), "vendor": vendor, "product": product, "name": name,
        "added": v.get("dateAdded", ""), "due": v.get("dueDate", ""),
        "ransom": v.get("knownRansomwareCampaignUse", "") == "Known",
        "ours": any(k in vendor.lower() for k in OUR_VENDORS),
        "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sol": SOL.get(cat, SOL[DEFAULT_CAT]),
    }

def psirt_item(x):
    desc = x.get("desc", "")
    atk, eff, lvl = classify(x["title"], desc)
    cat = categorize(x["title"])
    if cat == DEFAULT_CAT: cat = "Cisco 장비·SW"
    m = re.search(r"(?:Impact Rating|Severity)\W{0,6}(Critical|High|Medium|Low)", desc, re.I)
    sev = SEV_KO.get(m.group(1).capitalize(), "") if m else ""
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)$", "", x["title"])
    return {"title": title, "link": x.get("link", ""), "ts": x["ts"], "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sev": sev}

def fetch_news():
    items, ok = [], 0
    for name, url in NEWS_FEEDS:
        try:
            items += parse_rss(url, name)
            ok += 1
        except Exception as e: pass
    if ok == 0: raise RuntimeError("모든 뉴스 피드 실패")
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: x["ts"], reverse=True):
        key = re.sub(r"\W", "", it["title"])[:30]
        if key in seen: continue
        seen.add(key)
        it.pop("desc", None)
        uniq.append(it)
    cutoff = time.time() - 48 * 3600
    recent = [x for x in uniq if x["ts"] >= cutoff]
    return (recent if len(recent) >= 12 else uniq)[:30]

def load_kev():
    global _KEV_CACHE
    if _KEV_CACHE is None: _KEV_CACHE = json.loads(http_get(KEV_URL, 40).decode("utf-8"))
    return _KEV_CACHE

def fetch_kev():
    data = load_kev()
    vulns = sorted(data.get("vulnerabilities", []), key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)[:15]
    return [kev_item(v) for v in vulns]

def fetch_nvd():
    global _NVD_TOTAL
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=2)
    q = urllib.parse.urlencode({"cvssV3Severity": "CRITICAL", "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"), "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"), "resultsPerPage": 50})
    data = json.loads(http_get("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, 40).decode("utf-8"))
    out = []
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        score = 0
        for k in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30"):
            if c.get("metrics", {}).get(k):
                score = c["metrics"][k][0]["cvssData"].get("baseScore", 0)
                break
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        atk, eff, lvl = classify(desc)
        out.append({"cve": c.get("id", ""), "score": score, "desc": clean(desc)[:110], "atk": atk, "eff": eff, "lvl": lvl, "cat": categorize(desc), "prod": guess_product(clean(desc))})
    out.sort(key=lambda x: x["score"], reverse=True)
    _NVD_TOTAL = int(data.get("totalResults", len(out)) or 0)
    return out[:12]

def fetch_psirt():
    items = parse_rss(CISCO_PSIRT, "Cisco")
    items.sort(key=lambda x: x["ts"], reverse=True)
    return [psirt_item(x) for x in items[:12]]

DATE_RE = re.compile(r"(20\d{2})\s*[.\-/]\s*(\d{1,2})\s*[.\-/]\s*(\d{1,2})")

def find_dates(text):
    out = []
    for m in DATE_RE.finditer(text or ""):
        try: out.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError: pass
    return out

def event_type(title, given=""):
    if given: return given
    for label, keys in EVENT_TYPES:
        if any(k in title for k in keys): return label
    return "행사"

def passes(title, need_event):
    low = title.lower()
    if not any(k in low for k in SEC_KW): return False
    if any(w in title for w in EXCLUDE_WORDS) or any(w in title for w in PAST_WORDS): return False
    if need_event and not (any(w in title for w in EVENT_WORDS) or any(w in title for w in ACTION_WORDS)): return False
    return True

def load_registered_events():
    today = dt.datetime.now(KST).date()
    out = []
    if not EVENTS_FILE.exists(): return out
    try: arr = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    except Exception: return out
    for e in arr:
        try:
            s = dt.date.fromisoformat(str(e["date"]))
            en = dt.date.fromisoformat(str(e.get("end") or e["date"]))
        except Exception: continue
        if en < today: continue
        title = e.get("title", "")
        out.append({"kind": "event", "src": "등록", "type": event_type(title, e.get("type", "")), "date": s.isoformat(), "end": en.isoformat(), "time": e.get("time", ""), "title": title, "place": e.get("place", ""), "link": e.get("link", "")})
    out.sort(key=lambda x: (x["date"], x["title"]))
    return out[:10]

def scrape_site(site):
    page = decode_html(http_get(site["url"], 30))
    today = dt.datetime.now(KST).date()
    out, seen = [], set()
    for m in re.finditer(r"<a\b([^>]*)>(.*?)</a>", page, re.S | re.I):
        attrs, inner = m.group(1), m.group(2)
        if site["require_param"] not in html.unescape(attrs): continue
        title = clean(inner)
        if len(title) < 6 or not passes(title, site.get("need_event", True)): continue
        key = re.sub(r"\W", "", title)[:30]
        if key in seen: continue
        seen.add(key)
        hm = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", attrs, re.I)
        href = html.unescape(hm.group(1)).strip() if hm else ""
        link = site["url"] if not href or href.lower().startswith("javascript") or href.startswith("#") else urllib.parse.urljoin(site["url"], href)
        if not link.startswith(site["domain"]): link = site["url"]
        ds = find_dates(clean(page[m.end(): m.end() + 400]))
        posted = ds[0] if ds else None
        if posted and (today - posted).days > 60: continue
        ts = int(dt.datetime.combine(posted, dt.time(12), KST).timestamp()) if posted else 0
        out.append({"kind": "site", "src": site.get("label", site["name"]), "type": event_type(title), "title": title, "link": link, "ts": ts, "posted": posted.isoformat() if posted else ""})
    return out

def fetch_bexco():
    page = decode_html(http_get(BEXCO_URL, 30))
    today = dt.datetime.now(KST).date()
    out, seen = [], set()
    for blk in re.findall(r"<(?:li|tr)\b.*?</(?:li|tr)>", page, re.S | re.I):
        text = clean(blk)
        ds = find_dates(text)
        if not ds: continue
        s, e = ds[0], (ds[1] if len(ds) > 1 else ds[0])
        if e < s: e = s
        if e < today: continue
        dm = DATE_RE.search(text)
        head = text[:dm.start()].strip()
        tail = DATE_RE.sub("", text[dm.end():], count=1).replace("~", " ").strip()
        head = re.sub(r"^(?:상세보기|진행중|D-\d+|D-day|이벤트|회의|전시|공연|컨벤션|\s)+", "", head).strip()
        if len(head) < 4 or not any(k in head.lower() for k in SEC_KW): continue
        if any(w in head for w in EXCLUDE_WORDS): continue
        key = re.sub(r"\W", "", head)[:30] + s.isoformat()
        if key in seen: continue
        seen.add(key)
        hm = re.search(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"']", blk, re.I)
        href = html.unescape(hm.group(1)).strip() if hm else ""
        link = BEXCO_URL if not href or href.lower().startswith("javascript") or href.startswith("#") else urllib.parse.urljoin(BEXCO_URL, href)
        out.append({"kind": "event", "src": "벡스코", "type": event_type(head), "date": s.isoformat(), "end": e.isoformat(), "time": "", "title": head, "place": "벡스코 " + tail[:30].strip(), "link": link})
    out.sort(key=lambda x: (x["date"], x["title"]))
    return out[:6]

def fetch_events():
    reg = load_registered_events()
    bex = []
    try: bex = fetch_bexco()
    except Exception: pass
    sites, seen = [], set()
    for site in TARGET_SITES:
        try:
            got = scrape_site(site)
            for g in got:
                key = re.sub(r"\W", "", g["title"])[:30]
                if key not in seen:
                    seen.add(key)
                    sites.append(g)
        except Exception: continue
    sites.sort(key=lambda x: x["ts"], reverse=True)
    return (reg + bex + sites[:12])[:20]

def fetch_weather():
    q = urllib.parse.urlencode({"latitude": BUSAN[0], "longitude": BUSAN[1], "current": "temperature_2m,weather_code", "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max", "timezone": "Asia/Seoul", "forecast_days": 7})
    d = json.loads(http_get("https://api.open-meteo.com/v1/forecast?" + q).decode("utf-8"))
    dd = d["daily"]
    days = []
    for i, t in enumerate(dd["time"]):
        days.append({"date": t, "code": dd["weather_code"][i], "max": round(dd["temperature_2m_max"][i]), "min": round(dd["temperature_2m_min"][i]), "pop": dd["precipitation_probability_max"][i]})
    return {"temp": round(d["current"]["temperature_2m"]), "code": d["current"]["weather_code"], "days": days}

def build_stats(psirt, prev_nvd=0):
    kev = _KEV_CACHE
    if not kev: raise RuntimeError("KEV 데이터 없음")
    anchor = dt.datetime.now(dt.timezone.utc).date()
    s30 = (anchor - dt.timedelta(days=29)).isoformat()
    s7 = (anchor - dt.timedelta(days=6)).isoformat()
    s1 = (anchor - dt.timedelta(days=1)).isoformat()

    types, total30, new2, ours7_ids = {}, 0, 0, []
    vulns = sorted(kev.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
    for v in vulns:
        a = v.get("dateAdded", "")
        if a < s30: break
        if a >= s1: new2 += 1
        lab = classify(v.get("vulnerabilityName", ""), v.get("shortDescription", ""))[0]
        if lab == DEFAULT_ATK[0]: lab = "기타"
        types[lab] = types.get(lab, 0) + 1
        total30 += 1
        ours = any(k in v.get("vendorProject", "").lower() for k in OUR_VENDORS)
        if ours and a >= s7: ours7_ids.append(v.get("cveID", ""))

    now = time.time()
    psirt_hi = any(p.get("sev") in ("치명", "높음") and now - p.get("ts", 0) <= 86400 for p in (psirt or []))
    nvd = _NVD_TOTAL if _NVD_TOTAL is not None else prev_nvd
    score = min(new2, 8) + 3 * min(len(ours7_ids), 2) + (2 if nvd >= 5 else 0) + (3 if psirt_hi else 0)
    level = "경계" if score >= THREAT_HIGH else ("주의" if score >= THREAT_MID else "안정")

    items = sorted([(k, n) for k, n in types.items() if k != "기타"], key=lambda x: -x[1])
    top = items[:4]
    rest = sum(n for _, n in items[4:]) + types.get("기타", 0)
    if rest: top.append(("기타", rest))
    return {"types": [{"name": k, "n": n} for k, n in top], "total30": total30, "new2": new2, "ours7": len(ours7_ids), "ours7_ids": ours7_ids[:3], "nvd": nvd, "score": score, "level": level}

def load_prev():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo: return {}
    owner, name = repo.split("/", 1)
    try:
        url = "https://%s.github.io/%s/data.json?%d" % (owner, name, int(time.time()))
        return json.loads(http_get(url, 15).decode("utf-8"))
    except Exception: return {}

def main():
    prev = load_prev()
    data = {"generated": int(time.time()), "errors": []}
    jobs = (("news", fetch_news, []), ("kev", fetch_kev, []), ("nvd", fetch_nvd, []), ("psirt", fetch_psirt, []), ("events", fetch_events, []), ("weather", fetch_weather, {}))
    for key, fn, empty in jobs:
        try: data[key] = fn()
        except Exception as e:
            data["errors"].append(key)
            data[key] = prev.get(key, empty)
    try: data["stats"] = build_stats(data.get("psirt", []), (prev.get("stats") or {}).get("nvd", 0))
    except Exception:
        data["errors"].append("stats")
        data["stats"] = prev.get("stats", {})
    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    (OUT / "index.html").write_text(INDEX_HTML.replace("__AUTO__", json.dumps(AUTO)), encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")

# ----------------------------- 화면 HTML (국내행사 잘림 방지 및 NVD/PSIRT 가로 컴팩트 행 디자인 적용) -----------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BEE TECHNOLOGY 보안 전광판</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:100%;background:#050A16;overflow:hidden;font-family:'Noto Sans KR','Malgun Gothic','Apple SD Gothic Neo',sans-serif;color:#E5EEF9}
/* 높이 여유를 주어 하단 국내 보안 행사가 절대 잘리지 않도록 그리드 행 높이 최적화 */
#board{position:absolute;left:50%;top:50%;width:1080px;height:1920px;transform-origin:center center;
 background:radial-gradient(ellipse at 20% 0%,#0F2A4A 0%,#0A1428 45%,#050A16 100%);
 padding:12px;display:grid;grid-template-rows:100px 58px 135px 235px 235px 175px 175px 150px 210px 45px 26px;row-gap:6px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:16px;padding:10px 18px;overflow:hidden;position:relative}
.hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:6px}
.ttl{font-size:24px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;padding-left:10px;border-left:5px solid #22D3EE;line-height:1.1;min-width:0}
.ttl small{font-size:16px;font-weight:500;color:#7C93B2;margin-left:8px}
.pg{display:flex;align-items:center;flex:none;margin-left:8px}
.pb{width:38px;height:32px;border:0;border-radius:8px;background:rgba(34,211,238,.15);color:#22D3EE;font-size:24px;font-weight:900;line-height:30px;cursor:pointer;margin-left:4px}
.pb:hover,.pb:focus{outline:2px solid #22D3EE;outline-offset:1px}
.pd{display:inline-block;margin:0 4px;min-width:38px;text-align:center;font-size:18px;font-weight:700;color:#7C93B2}
.fade{transition:opacity .25s ease;min-height:0}
.fade.out{opacity:0}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
/* 헤더 */
#head{display:grid;grid-template-columns:1fr auto;align-items:center;padding:0 8px}
.brand{display:flex;align-items:center}
.brand svg{margin-right:14px}
.brand b{font-size:36px;font-weight:900;letter-spacing:-1px;display:block;line-height:1.1}
.brand span{font-size:18px;color:#7C93B2}
.clock{text-align:right}
#clock{font-size:54px;font-weight:900;color:#22D3EE;line-height:54px;letter-spacing:-2px}
#date{font-size:20px;font-weight:700;line-height:24px}
/* 상태 바 */
#status{display:flex;align-items:center;padding:4px 14px}
.chip{display:flex;align-items:baseline;font-size:18px;font-weight:700;padding:3px 12px;border-radius:10px;background:rgba(255,255,255,.08);margin-right:18px;white-space:nowrap}
.chip b{font-size:26px;font-weight:900;margin-left:6px}
.chip small{font-size:12px;margin-left:6px;opacity:.7;font-weight:500}
.chip.lv0{background:#34D399;color:#04281c}
.chip.lv1{background:#FACC15;color:#111}
.chip.lv2{background:#F97316;color:#111}
#stats{display:flex;flex:1;justify-content:space-between}
.st{display:flex;align-items:baseline;white-space:nowrap}
.st .lb{font-size:16px;color:#9FB4CE;margin-right:6px}
.st b{font-size:32px;font-weight:900;color:#22D3EE;line-height:1}
.st em{font-style:normal;font-size:16px;color:#9FB4CE;margin-left:2px}
.st .cid{font-family:Consolas,monospace;font-size:14px;color:#F97316;margin-left:6px}
/* 날씨 */
#wx{display:grid;grid-template-columns:250px 1fr;column-gap:14px;padding:8px 14px}
.now{border-right:1px solid rgba(34,211,238,.18);padding-right:12px}
.now .big{font-size:48px;font-weight:900;line-height:1}
.now .cond{font-size:20px;font-weight:700;color:#A9C1DE;line-height:24px}
.week{display:grid;grid-template-columns:repeat(7,1fr);column-gap:6px}
.day{text-align:center;border-radius:10px;padding:2px 2px;background:rgba(255,255,255,.04)}
.day.today{border:2px solid #22D3EE;background:rgba(34,211,238,.1)}
.day.rain{background:rgba(59,130,246,.22)}
.day .dn{font-size:18px;font-weight:700;line-height:22px}
.day .dd{font-size:13px;color:#7C93B2;line-height:14px}
.day .tt{font-size:18px;font-weight:700;line-height:22px}
.day .tt i{font-style:normal;color:#7C93B2;font-weight:500}
.day .pp{font-size:14px;color:#60A5FA;line-height:16px}
/* 뉴스 행 */
.row{display:grid;grid-template-columns:95px 1fr 75px;column-gap:10px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:0}
.src{font-size:16px;font-weight:700;text-align:center;border-radius:6px;padding:3px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.t{font-size:22px;font-weight:700;line-height:1.25;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ago{font-size:16px;color:#7C93B2;text-align:right}
/* 긴급 취약점 (KEV) */
.kev{display:grid;grid-template-columns:200px 1fr 110px;column-gap:10px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.kev:last-child{border-bottom:0}
.cve{font-family:Consolas,monospace;font-size:21px;font-weight:700;color:#22D3EE}
.kev .a{font-size:22px;font-weight:700;line-height:26px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kev .b{font-size:17px;line-height:22px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.due{font-size:16px;text-align:right;color:#F97316;font-weight:700}
.tag{display:inline-block;font-size:14px;font-weight:900;padding:1px 6px;border-radius:5px;margin-right:6px;vertical-align:middle}
.tag.our{background:#F97316;color:#111}
.tag.rw{background:#EF4444;color:#fff}
.atk{display:inline-block;font-size:15px;font-weight:900;padding:1px 8px;border-radius:5px;margin-right:6px;vertical-align:middle;line-height:20px}
.l1{background:#EF4444;color:#fff}.l2{background:#F97316;color:#111}.l3{background:#FACC15;color:#111}
.sol{color:#22D3EE;font-weight:700}

/* 신규 Critical CVE 및 Cisco PSIRT 가독성 개선 가로 행 컴팩트 디자인 */
.nvd-row{display:grid;grid-template-columns:130px 1fr 130px;column-gap:12px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.nvd-row:last-child{border-bottom:0}
.sc9{background:#EF4444;color:#fff;font-size:16px;font-weight:900;padding:3px 8px;border-radius:6px;text-align:center;white-space:nowrap}
.sc7{background:#F97316;color:#111;font-size:16px;font-weight:900;padding:3px 8px;border-radius:6px;text-align:center;white-space:nowrap}

.psirt-row{display:grid;grid-template-columns:95px 1fr 75px;column-gap:10px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.psirt-row:last-child{border-bottom:0}

/* 차트 */
#chart{display:grid;grid-template-columns:1fr;padding:8px 18px}
.dn2{display:flex;align-items:center;height:100px}
.dnw{position:relative;width:96px;height:96px;margin-right:20px;flex:none}
.dnc{position:absolute;left:0;top:0;width:96px;height:96px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.dnc b{font-size:26px;font-weight:900;line-height:1}
.dnc span{font-size:13px;color:#7C93B2}
.lgs{display:grid;grid-template-columns:1fr 1fr;column-gap:18px;row-gap:2px;flex:1}
.lg{font-size:17px;line-height:21px;white-space:nowrap;display:flex;align-items:center}
.lg i{width:11px;height:11px;border-radius:3px;margin-right:7px;flex:none}
.lg b{margin-left:auto;color:#22D3EE;font-size:17px}
/* 국내 보안행사 */
.ev{display:grid;grid-template-columns:1fr 105px;column-gap:12px;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.ev:last-child{border-bottom:0}
.evl{display:flex;align-items:center;margin-bottom:1px}
.dt{font-size:17px;font-weight:900;color:#22D3EE;white-space:nowrap;margin-right:8px}
.tt2{font-size:20px;font-weight:700;line-height:24px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pl{font-size:14px;line-height:18px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.evm{min-width:0}
.bd{font-size:16px;font-weight:900;text-align:center;border-radius:6px;padding:3px 0;background:rgba(34,211,238,.15);color:#22D3EE;white-space:nowrap}
.bd.hot{background:#EF4444;color:#fff}
.bd.soon{background:#F97316;color:#111}
.bd.nw{background:rgba(255,255,255,.08);color:#9FB4CE;font-weight:500;font-size:14px}
.tg{display:inline-block;font-size:13px;font-weight:900;padding:1px 6px;border-radius:5px;margin-right:6px;vertical-align:middle;white-space:nowrap}
.tgE{background:#34D399;color:#04281c}
.tgS{background:#F97316;color:#111}
.tgN{background:rgba(34,211,238,.2);color:#22D3EE}
/* 티커 */
#ticker{padding:0 16px;display:flex;align-items:center;overflow:hidden}
.live{font-size:17px;font-weight:900;color:#22D3EE;margin-right:14px;white-space:nowrap;display:flex;align-items:center}
.live i{display:inline-block;width:11px;height:11px;border-radius:50%;background:#34D399;margin-right:7px;animation:blink 1s infinite}
#tkmask{flex:1;overflow:hidden;white-space:nowrap}
#tk{display:inline-block;white-space:nowrap;will-change:transform}
@keyframes tkscroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ti{display:inline-block;font-size:21px;font-weight:700;margin-right:50px}
.tg2{display:inline-block;font-size:15px;font-weight:900;padding:1px 8px;border-radius:5px;margin-right:8px;vertical-align:middle}
.tgC{background:#F97316;color:#111}
/* 링크 */
a.lk{color:inherit;text-decoration:none;cursor:pointer}
a.mini{display:block}
a.lk:hover,a.lk:focus{outline:2px solid #22D3EE;outline-offset:2px;border-radius:6px;background:rgba(34,211,238,.08)}
#foot{display:flex;justify-content:space-between;align-items:center;font-size:17px;color:#7C93B2;padding:0 8px}
#foot .bad{color:#FACC15;font-weight:900}
.pulse{display:inline-block;width:9px;height:9px;border-radius:50%;background:#34D399;margin-right:7px;animation:blink 2s infinite}
</style>
</head>
<body>
<div id="board">
  <!-- 1. 헤더 -->
  <div id="head">
    <div class="brand">
      <svg width="350" height="90" viewBox="0 0 370 100">
        <defs>
          <linearGradient id="lgO" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#F9A83F"/><stop offset="1" stop-color="#E8590C"/></linearGradient>
          <linearGradient id="lgG1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#C9C9C9"/><stop offset="1" stop-color="#9A9A9A"/></linearGradient>
          <linearGradient id="lgG2" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#8E8E8E"/><stop offset="1" stop-color="#5F5F5F"/></linearGradient>
          <linearGradient id="lgG3" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#E3E3E3"/><stop offset="1" stop-color="#BDBDBD"/></linearGradient>
        </defs>
        <g stroke="#0A1428" stroke-width="2.6" stroke-linejoin="round">
          <polygon points="48,6 86.1,28 63.6,41 48,32" fill="url(#lgO)"/>
          <polygon points="86.1,28 86.1,72 63.6,59 63.6,41" fill="url(#lgO)"/>
          <polygon points="86.1,72 48,94 48,68 63.6,59" fill="url(#lgG2)"/>
          <polygon points="48,94 9.9,72 32.4,59 48,68" fill="url(#lgG1)"/>
          <polygon points="9.9,72 9.9,28 32.4,41 32.4,59" fill="url(#lgG3)"/>
          <polygon points="9.9,28 48,6 48,32 32.4,41" fill="url(#lgG3)"/>
          <polygon points="48,32 63.6,41 63.6,59 48,68 32.4,59 32.4,41" fill="#E6E6E6"/>
        </g>
        <text x="106" y="58" font-family="'Malgun Gothic','Noto Sans KR',sans-serif" font-size="29" font-weight="900" fill="#FFFFFF">(주)비테크놀로지</text>
        <text x="108" y="83" font-family="Arial,'Noto Sans KR',sans-serif" font-size="17" font-weight="700" letter-spacing="1.6" fill="#9FB4CE">BEE TECHNOLOGY</text>
      </svg>
      <div style="margin-left:18px"><b style="font-size:32px">오늘의 보안 브리핑</b><span>Daily Security Briefing</span></div>
    </div>
    <div class="clock"><div id="clock">--:--</div><div id="date"></div></div>
  </div>

  <!-- 2. 상태 바 -->
  <div id="status" class="panel">
    <div id="chip" class="chip lv0">위협 수준<b>-</b><small>자체 산정</small></div>
    <div id="stats">
      <div class="st"><span class="lb">신규 악용(2일)</span><b id="c1">0</b><em>건</em></div>
      <div class="st"><span class="lb">Critical CVE(2일)</span><b id="c2">0</b><em>건</em></div>
      <div class="st"><span class="lb">취급 제품(7일)</span><b id="c3">0</b><em>건</em><span class="cid" id="c3id"></span></div>
    </div>
  </div>

  <!-- 3. 날씨 -->
  <div id="wx" class="panel"></div>

  <!-- 4. 오늘의 보안뉴스 -->
  <div class="panel">
    <div class="hd"><div class="ttl">오늘의 보안뉴스<small>어제·오늘</small></div>
      <div class="pg"><button class="pb" onclick="nav('news',-1)">&lsaquo;</button><span class="pd" id="d-news"></span><button class="pb" onclick="nav('news',1)">&rsaquo;</button></div></div>
    <div id="news" class="fade"></div>
  </div>

  <!-- 5. 긴급 취약점 (KEV) -->
  <div class="panel">
    <div class="hd"><div class="ttl">긴급 취약점<small>실제 공격에 악용 중 · 위험 유형과 우리 대응 솔루션</small></div>
      <div class="pg"><button class="pb" onclick="nav('kev',-1)">&lsaquo;</button><span class="pd" id="d-kev"></span><button class="pb" onclick="nav('kev',1)">&rsaquo;</button></div></div>
    <div id="kev" class="fade"></div>
  </div>

  <!-- 6. 신규 Critical CVE (NVD) - 가로 행 컴팩트 디자인 적용 -->
  <div class="panel">
    <div class="hd"><div class="ttl">신규 Critical CVE <small>NVD · 최근 48시간</small></div>
      <div class="pg"><button class="pb" onclick="nav('nvd',-1)">&lsaquo;</button><span class="pd" id="d-nvd"></span><button class="pb" onclick="nav('nvd',1)">&rsaquo;</button></div></div>
    <div id="nvd" class="fade"></div>
  </div>

  <!-- 7. Cisco 보안 권고 (PSIRT) - 가로 행 컴팩트 디자인 적용 -->
  <div class="panel">
    <div class="hd"><div class="ttl">Cisco 보안 권고</div>
      <div class="pg"><button class="pb" onclick="nav('psirt',-1)">&lsaquo;</button><span class="pd" id="d-psirt"></span><button class="pb" onclick="nav('psirt',1)">&rsaquo;</button></div></div>
    <div id="psirt" class="fade"></div>
  </div>

  <!-- 8. 공격 유형 비율 차트 -->
  <div id="chart" class="panel">
    <div class="hd" style="margin-bottom:2px"><div class="ttl">공격 유형 비율<small>CISA 악용 취약점 · 최근 30일</small></div></div>
    <div id="donut"></div>
  </div>

  <!-- 9. 국내 보안 행사 (여유 공간 확보로 잘림 현상 완전 해결) -->
  <div class="panel">
    <div class="hd"><div class="ttl">국내 보안 행사<small>교육·세미나·컨퍼런스 · 벡스코·부산 기관</small></div>
      <div class="pg"><button class="pb" onclick="nav('events',-1)">&lsaquo;</button><span class="pd" id="d-events"></span><button class="pb" onclick="nav('events',1)">&rsaquo;</button></div></div>
    <div id="events" class="fade"></div>
  </div>

  <!-- 10. 하단 티커 -->
  <div id="ticker" class="panel"><span class="live"><i></i>LIVE</span><div id="tkmask"><div id="tk"></div></div></div>

  <!-- 11. 풋터 -->
  <div id="foot"><span><i class="pulse"></i><span id="upd">데이터 확인 중...</span></span><span>BEE TECHNOLOGY Security Board</span></div>
</div>

<script>
var AUTO=__AUTO__;
var W=1080,H=1920,DATA=null,DAYS=['일','월','화','수','목','금','토'];
function $(id){return document.getElementById(id)}
function pad(n){return n<10?'0'+n:''+n}
function esc(s){return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]})}
function fit(){var s=Math.min(window.innerWidth/W,window.innerHeight/H);$('board').style.transform='translate(-50%,-50%) scale('+s+')'}
window.addEventListener('resize',fit);fit();

var NVD='https://nvd.nist.gov/vuln/detail/';
function A(cls,url,inner){
 if(!/^https?:\/\//i.test(url||''))return '<div class="'+cls+'">'+inner+'</div>';
 return '<a class="'+cls+' lk" href="'+esc(url)+'" target="_blank" rel="noopener">'+inner+'</a>'}

function tick(){
 var d=new Date();
 $('clock').textContent=pad(d.getHours())+':'+pad(d.getMinutes());
 $('date').textContent=d.getFullYear()+'.'+pad(d.getMonth()+1)+'.'+pad(d.getDate())+' ('+DAYS[d.getDay()]+')';
 if(DATA){var m=Math.floor((d.getTime()/1000-DATA.generated)/60),el=$('upd');
  if(m>60){el.innerHTML='<span class="bad">갱신 지연 ('+m+'분 전 데이터)</span>'}
  else{el.textContent='마지막 갱신 '+(m<1?'방금':m+'분 전')+(DATA.errors&&DATA.errors.length?' (일부 수집 실패: '+DATA.errors.join(', ')+')':'')}}
}
function ago(ts){if(!ts)return '';var m=Math.floor((Date.now()/1000-ts)/60);if(m<60)return Math.max(m,1)+'분 전';var h=Math.floor(m/60);return h<24?h+'시간 전':Math.floor(h/24)+'일 전'}

function kind(c){if(c<=1)return 'sun';if(c==2)return 'part';if(c==3)return 'cloud';if(c==45||c==48)return 'fog';if((c>=71&&c<=77)||c==85||c==86)return 'snow';return 'rain'}
function label(c){var k=kind(c);return {sun:'맑음',part:'구름조금',cloud:'흐림',fog:'안개',snow:'눈',rain:c>=95?'뇌우':'비'}[k]}
var CL='<path d="M14 38a8 8 0 0 1 2-15 11 11 0 0 1 21 3 7 7 0 0 1-1 12z" fill="#CBD5E1"/>';
function ico(c,s){var k=kind(c),b='';
 if(k=='sun')b='<circle cx="28" cy="28" r="10" fill="#FBBF24"/><g stroke="#FBBF24" stroke-width="3" stroke-linecap="round"><path d="M28 6v6M28 44v6M6 28h6M44 28h6M12 12l4 4M40 40l4 4M44 12l-4 4M16 40l-4 4"/></g>';
 else if(k=='part')b='<circle cx="20" cy="20" r="9" fill="#FBBF24"/>'+CL;
 else if(k=='cloud')b=CL;
 else if(k=='fog')b='<g stroke="#94A3B8" stroke-width="4" stroke-linecap="round"><path d="M10 20h36M6 30h44M12 40h32"/></g>';
 else if(k=='snow')b=CL+'<g fill="#fff"><circle cx="20" cy="46" r="3"/><circle cx="30" cy="50" r="3"/><circle cx="40" cy="46" r="3"/></g>';
 else b=CL+'<g stroke="#60A5FA" stroke-width="3.5" stroke-linecap="round"><path d="M20 43l-3 8M30 43l-3 8M40 43l-3 8"/></g>';
 return '<svg width="'+s+'" height="'+s+'" viewBox="0 0 56 56">'+b+'</svg>'}

function todayStr(){var t=new Date();return t.getFullYear()+'-'+pad(t.getMonth()+1)+'-'+pad(t.getDate())}
function dnum(s){var p=s.split('-');return Date.UTC(+p[0],+p[1]-1,+p[2])/864e5}
function md(s){var p=s.split('-'),dd=new Date(+p[0],+p[1]-1,+p[2]);return pad(+p[1])+'/'+pad(+p[2])+'('+DAYS[dd.getDay()]+')'}

function renderWx(w){
 if(!w||!w.days){$('wx').innerHTML='<div class="empty">날씨 데이터 없음</div>';return}
 var ts=todayStr();
 var h='<div class="now"><div class="ttl" style="margin-bottom:2px">부산 날씨</div><div style="display:flex;align-items:center">'+ico(w.code,48)+'<div class="big" style="margin-left:6px">'+w.temp+'°</div></div><div class="cond">'+label(w.code)+' · 최고 '+w.days[0].max+'° / 최저 '+w.days[0].min+'°</div></div><div class="week">';
 for(var i=0;i<w.days.length;i++){var d=w.days[i],dt=new Date(d.date+'T00:00:00'),rain=kind(d.code)=='rain'||kind(d.code)=='snow';
  h+='<div class="day'+(d.date==ts?' today':'')+(rain?' rain':'')+'"><div class="dn">'+(d.date==ts?'오늘':DAYS[dt.getDay()])+'</div><div class="dd">'+pad(dt.getMonth()+1)+'/'+pad(dt.getDate())+'</div>'+ico(d.code,34)+'<div class="tt">'+d.max+'° <i>'+d.min+'°</i></div><div class="pp">강수 '+d.pop+'%</div></div>'}
 $('wx').innerHTML=h+''}

var LIST={news:[],kev:[],nvd:[],psirt:[],events:[]};
var PER={news:3,kev:3,nvd:3,psirt:3,events:2};
var MAXP={news:4,kev:3,nvd:4,psirt:4,events:6};
var PAGE={news:0,kev:0,nvd:0,psirt:0,events:0};
var SUPPRESS=0;

function evHtml(e){
 var ts=todayStr(),tn=dnum(ts),t=esc(e.type||'행사');
 if(e.kind=='event'){
  var sd=dnum(e.date),ed=dnum(e.end),bd,bc='';
  if(tn>=sd&&tn<=ed){bd=(sd==ed)?'오늘':'진행중';bc=' hot'}
  else{var df=sd-tn;bd='D-'+df;if(df<=7)bc=' soon'}
  var dtx=md(e.date)+(e.end!=e.date?' ~ '+md(e.end):'')+(e.time?' '+esc(e.time):'');
  var st=(e.src&&e.src!='등록')?'<span class="tg tgE">'+esc(e.src)+'</span>':'';
  return A('ev',e.link,'<div class="evm"><div class="evl"><span class="dt">'+dtx+'</span>'+st+'<span class="tg tgN">'+t+'</span></div><div class="tt2">'+esc(e.title)+'</div>'+(e.place?'<div class="pl">'+esc(e.place)+'</div>':'')+'</div><span class="bd'+bc+'">'+bd+'</span>')}
 if(e.kind=='site'){
  return A('ev',e.link,'<div class="evm"><div class="evl"><span class="tg tgS">'+esc(e.src||'공고')+'</span><span class="tg tgN">'+t+'</span></div><div class="tt2">'+esc(e.title)+'</div><div class="pl">'+(e.posted?md(e.posted)+' 게시 · ':'')+'일정은 원문에서 확인</div></div><span class="bd nw">공고</span>')}
 return A('ev',e.link,'<div class="evm"><div class="evl"><span class="tg tgS">모집·공지</span><span class="tg tgN">'+t+'</span></div><div class="tt2">'+esc(e.title)+'</div><div class="pl">'+ago(e.ts)+' 보도 · 날짜는 원문 확인</div></div><span class="bd nw">검색</span>')}

var RENDER={
 news:function(n){return A('row',n.link,'<span class="src">'+esc(n.src)+'</span><div class="t">'+esc(n.title)+'</div><span class="ago">'+ago(n.ts)+'</span>')},
 kev:function(v){return A('kev',NVD+v.cve,'<div class="cve">'+esc(v.cve)+'</div><div><div class="a">'+(v.ours?'<span class="tag our">취급</span>':'')+(v.ransom?'<span class="tag rw">랜섬웨어</span>':'')+'<span class="atk l'+(v.lvl||3)+'">'+esc(v.atk)+'</span>'+esc(v.vendor)+' '+esc(v.product)+'</div><div class="b">'+esc(v.cat)+' · '+esc(v.eff)+' <span class="sol">→ '+esc(v.sol)+'</span></div></div><div class="due">조치 '+esc(String(v.due).slice(5))+'</div>')},
 nvd:function(n){return A('nvd-row',NVD+n.cve,'<div class="'+(n.score>=9?'sc9':'sc7')+'">CVSS '+n.score+'</div><div style="min-width:0"><div style="font-size:19px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span class="atk l'+(n.lvl||3)+'">'+esc(n.atk)+'</span>'+esc(n.prod)+'</div><div style="font-size:15px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(n.cat)+' · '+esc(n.eff)+'</div></div><div style="font-family:Consolas,monospace;font-size:17px;font-weight:700;color:#22D3EE;text-align:right">'+esc(n.cve)+'</div>')},
 psirt:function(p){return A('psirt-row',p.link,'<div class="src" style="background:rgba(59,130,246,.2);color:#60A5FA">'+esc(p.sev||'권고')+'</div><div style="min-width:0"><div style="font-size:19px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis"><span class="atk l'+(p.lvl||3)+'">'+esc(p.atk)+'</span>'+esc(p.title)+'</div><div style="font-size:14px;color:#7C93B2">'+ago(p.ts)+' 발표</div></div><div class="ago">Cisco</div>')},
 events:evHtml
};

function pages(name){return Math.max(1,Math.min(MAXP[name],Math.ceil(LIST[name].length/PER[name])))}
function paint(name){
 var n=pages(name);if(PAGE[name]>=n)PAGE[name]=0;
 var s=PAGE[name]*PER[name],items=LIST[name].slice(s,s+PER[name]),h='',i;
 for(i=0;i<items.length;i++)h+=RENDER[name](items[i]);
 $(name).innerHTML=h||'<div class="empty">데이터 없음</div>';
 var dd='';if(n>1){dd=(PAGE[name]+1)+' / '+n}
 $('d-'+name).textContent=dd}

function nav(name,dir){
 var n=pages(name);if(n<2)return;
 PAGE[name]=(PAGE[name]+dir+n)%n;
 var el=$(name);el.className='fade out';
 setTimeout(function(){paint(name);el.className='fade'},220)}

function bindSwipe(name){
 var el=$(name),sx=0,sy=0,drag=false;
 if(!el)return;
 el.addEventListener('pointerdown',function(e){sx=e.clientX;sy=e.clientY;drag=true});
 el.addEventListener('pointerup',function(e){
  if(!drag)return;drag=false;
  var dx=e.clientX-sx,dy=e.clientY-sy;
  if(Math.abs(dx)>60&&Math.abs(dx)>Math.abs(dy)*1.5){SUPPRESS=Date.now()+400;nav(name,dx<0?1:-1)}});
 el.addEventListener('click',function(e){if(Date.now()<SUPPRESS){e.preventDefault();e.stopPropagation()}},true)}

['news','kev','nvd','psirt','events'].forEach(function(n){
 bindSwipe(n);
 if(AUTO[n]>0)setInterval(function(){nav(n,1)},AUTO[n]*1000)});

function countTo(el,to){
 to=+to||0;
 var cur=el.getAttribute('data-v'),from=cur==null?0:+cur;
 if(cur==String(to))return;
 el.setAttribute('data-v',to);
 var step=0,steps=16;clearInterval(el._t);
 el._t=setInterval(function(){step++;el.textContent=Math.round(from+(to-from)*step/steps);if(step>=steps){clearInterval(el._t);el.textContent=to}},35)}

function renderStatus(st){
 st=st||{};
 var lv={'안정':0,'주의':1,'경계':2}[st.level];if(lv==null)lv=0;
 $('chip').className='chip lv'+lv;
 $('chip').innerHTML='위협 수준<b>'+esc(st.level||'-')+'</b><small>자체 산정</small>';
 countTo($('c1'),st.new2);countTo($('c2'),st.nvd);countTo($('c3'),st.ours7);
 $('c3id').textContent=(st.ours7_ids||[]).join(', ')}

var TSIG='',COLS=['#EF4444','#F97316','#FACC15','#22D3EE','#64748B'];
function renderDonut(st){
 var sig=JSON.stringify(st&&st.types);
 if(sig==TSIG)return;TSIG=sig;
 var ty=(st&&st.types)||[],t=0,i;
 for(i=0;i<ty.length;i++)t+=ty[i].n;
 if(!t){$('donut').innerHTML='<div class="empty">데이터 없음</div>';return}
 var C=2*Math.PI*32,cum=0,segs='',lg='';
 for(i=0;i<ty.length;i++){
  var len=C*ty[i].n/t,col=COLS[i%COLS.length];
  segs+='<circle cx="42" cy="42" r="32" fill="none" stroke="'+col+'" stroke-width="10" transform="rotate(-90 42 42)" style="stroke-dasharray:0 '+C+';transition:stroke-dasharray 1s ease" stroke-dashoffset="'+(-cum)+'" data-d="'+len+' '+(C-len)+'"/>';
  cum+=len;
  lg+='<div class="lg"><i style="background:'+col+'"></i>'+esc(ty[i].name)+'<b>'+ty[i].n+'건</b></div>'}
 $('donut').innerHTML='<div class="dn2"><div class="dnw"><svg width="84" height="84" viewBox="0 0 84 84"><circle cx="42" cy="42" r="32" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="10"/>'+segs+'</svg><div class="dnc"><b>'+t+'</b><span>30일</span></div></div><div class="lgs">'+lg+'</div></div>';
 setTimeout(function(){
  var cs=$('donut').getElementsByTagName('circle'),k;
  for(k=0;k<cs.length;k++){var dd=cs[k].getAttribute('data-d');if(dd)cs[k].style.strokeDasharray=dd}
 },80)}

var TK_LAST='';
function setTicker(html){
 if(html==TK_LAST)return;TK_LAST=html;
 var tk=$('tk');tk.style.animation='none';tk.innerHTML=html;
 var uw=tk.offsetWidth||1,mw=$('tkmask').offsetWidth||900;
 var n=Math.max(1,Math.ceil(mw/uw)),blk='',i;
 for(i=0;i<n;i++)blk+=html;
 tk.innerHTML=blk+blk;
 var bw=tk.offsetWidth/2;
 tk.style.animation='tkscroll '+Math.max(20,Math.round(bw/70))+'s linear infinite'}

function buildTicker(d){
 var u=[],nw=(d.news||[]).slice(0,8),kv=(d.kev||[]).slice(0,5),ts=todayStr(),i;
 var ev=(d.events||[]).filter(function(e){return e.kind=='event'&&e.end>=ts}).slice(0,2);
 for(i=0;i<nw.length;i++){
  u.push('<span class="ti"><b class="tg2 tgN">뉴스</b>'+esc(nw[i].title)+'</span>');
  if(kv[i])u.push('<span class="ti"><b class="tg2 tgC">CVE</b>'+esc(kv[i].cve)+' '+esc(kv[i].atk)+' · '+esc(kv[i].vendor)+' '+esc(kv[i].product)+'</span>')}
 for(i=0;i<ev.length;i++)u.push('<span class="ti"><b class="tg2 tgE">행사</b>'+md(ev[i].date)+' '+esc(ev[i].title)+'</span>');
 if(!u.length)u.push('<span class="ti">데이터를 불러오는 중입니다</span>');
 setTicker(u.join(''))}

function render(d){
 renderWx(d.weather);
 LIST.news=(d.news||[]).slice(0,12);
 LIST.kev=(d.kev||[]).slice(0,9);
 LIST.nvd=(d.nvd||[]).slice(0,12);
 LIST.psirt=(d.psirt||[]).slice(0,12);
 LIST.events=(d.events||[]).slice(0,12);

 paint('news');paint('kev');paint('nvd');paint('psirt');paint('events');

 renderStatus(d.stats);
 renderDonut(d.stats);
 buildTicker(d);
 tick()}

function load(){
 var x=new XMLHttpRequest();x.open('GET','data.json?'+Date.now(),true);
 x.onload=function(){
  try{DATA=JSON.parse(x.responseText);render(DATA)}
  catch(e){if(window.console)console.error('render error',e)}};
 x.send()}

load();setInterval(load,60000);setInterval(tick,1000);tick();
setTimeout(function(){location.reload()},6*3600*1000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
