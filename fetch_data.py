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
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)\$", "", x["title"])
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
    return {"temp": round(d["current"]["temperature_2m"]), "code
