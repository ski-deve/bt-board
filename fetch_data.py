#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 두 파일을 만듭니다.
  site/data.json   : 보안뉴스 / CISA KEV / NVD / Cisco 권고 / 국내 보안행사 / 부산 날씨 / 통계
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)

국내 보안행사 (우선순위 순서로 표시)
  1) events.json 에 직접 등록한 행사 (확정 일정, 날짜가 지나면 자동 숨김)
  2) 벡스코 행사일정 중 보안 관련 행사 (날짜 포함, D-day 표시)
  3) 부산 기관 게시판(TARGET_SITES)의 보안 관련 교육·세미나·행사 공고 (게시일 표시, 일정은 원문 확인)
  4) (선택) 뉴스 검색 후보 - USE_NEWS_SEARCH = True 일 때만
  events.json 예시:
  [{"date":"2026-12-03","end":"2026-12-03","time":"14:00","title":"행사명","place":"장소","link":"https://...","type":"교육"}]
  - end, time, place, link, type 은 생략 가능. type 생략 시 제목으로 자동 분류합니다.

외부 라이브러리 없이 파이썬 3 표준 라이브러리만 사용합니다.
로컬 테스트:  python fetch_data.py  ->  site 폴더에서  python -m http.server 8080
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
    ("KISA", "https://knvd.krcert.or.kr/rss/securityNotice.do"),  # 실패하면 이 줄을 지워도 됩니다
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUSAN = (35.1796, 129.0756)
EVENTS_FILE = Path("events.json")

# 위협 수준 (자체 산정 기준이며 국가 공식 경보 단계와 무관합니다)
#   점수 = 신규 악용(2일, 최대 8) + 취급 제품 해당(7일, 건당 3점, 최대 6) + Critical CVE 5건 이상(2점) + Cisco 치명·높음 권고(3점)
THREAT_MID = 5     # 이 점수 이상이면 "주의"
THREAT_HIGH = 10   # 이 점수 이상이면 "경계"

# 자동 넘김 간격(초). 0 이면 끔 (기본: 수동 넘김 - 버튼 또는 좌우 드래그)
AUTO = {"news": 0, "kev": 0, "nvd": 0, "psirt": 0, "events": 0}

# ---- 국내 보안행사 수집 대상 (부산 기관 게시판) ----
#   require_param : 게시글 링크(또는 속성)에 이 문자열이 있는 항목만 게시글로 인정
#   need_event    : True 면 제목에 행사 단어(세미나, 교육, 모집 등)도 있어야 통과
#   label         : 화면에 표시할 짧은 이름
TARGET_SITES = [
    {"name": "부산정보산업진흥원_ICT교육", "label": "BIPA 교육",
     "url": "https://bipa.kr/board/training/list", "domain": "https://bipa.kr",
     "require_param": "seq=", "need_event": False},
    {"name": "부산정보산업진흥원_일반공고", "label": "BIPA 공고",
     "url": "https://bipa.kr/board/notice/list", "domain": "https://bipa.kr",
     "require_param": "seq=", "need_event": True},
    {"name": "부산경제진흥원_소상공인디지털", "label": "BEPA",
     "url": "https://www.bepa.kr/kor/view.do?no=1502", "domain": "https://www.bepa.kr",
     "require_param": "idx=", "need_event": True},
    {"name": "부산경제진흥원_기업지원사업", "label": "BEPA",
     "url": "https://www.bepa.kr/kor/view.do?no=1505", "domain": "https://www.bepa.kr",
     "require_param": "idx=", "need_event": True},
    {"name": "부산과학기술고등교육진흥원_사업", "label": "BISTEP",
     "url": "https://www.bistep.re.kr/board.es?mid=a10301010000&bid=0002", "domain": "https://www.bistep.re.kr",
     "require_param": "nttSn=", "need_event": True},
    {"name": "부산상공회의소_교육행사", "label": "부산상의",
     "url": "https://www.bcci.or.kr/", "domain": "https://www.bcci.or.kr",
     "require_param": "seq=", "need_event": True},
    {"name": "부산지방중소벤처기업청_공고", "label": "부산중기청",
     "url": "https://www.mss.go.kr/site/busan/ex/bbs/List.do?cbIdx=277", "domain": "https://www.mss.go.kr",
     "require_param": "seq=", "need_event": True},
]
# 벡스코 행사일정 (보안 관련 제목만 표시)
BEXCO_URL = "https://www.bexco.co.kr/kor/CMS/EventScheduleMgr/list.do?mCode=MN214"

# 보안 관련 키워드 (제목에 하나라도 있어야 표시, 영문은 소문자로 비교). 필요하면 AI, 클라우드 등을 추가하세요.
SEC_KW = ["보안", "정보보호", "사이버", "해킹", "개인정보", "랜섬", "침해", "암호", "제로트러스트", "zero trust",
          "시큐리티", "security", "isms", "ciso", "망분리", "취약점", "포렌식", "위협", "방화벽"]
EXCLUDE_WORDS = ["입찰", "채용", "낙찰", "계약", "합격", "선정 결과", "결과 안내", "결과 공고", "용역"]
EVENT_WORDS = ["세미나", "교육", "컨퍼런스", "콘퍼런스", "워크숍", "웨비나", "설명회", "포럼", "아카데미",
               "해커톤", "강좌", "강연", "실습", "행사", "대회", "박람회", "전시"]
ACTION_WORDS = ["모집", "접수", "개최", "신청", "참가", "초청", "등록", "안내", "예정", "오픈"]
PAST_WORDS = ["성료", "마쳐", "마치", "성황", "폐막", "막내렸", "참가해", "참가했", "열렸", "진행했", "수료"]
EVENT_TYPES = [
    ("웨비나", ["웨비나", "온라인 강연"]),
    ("컨퍼런스", ["컨퍼런스", "콘퍼런스"]),
    ("교육", ["교육", "강좌", "아카데미", "실습", "훈련", "과정"]),
    ("세미나", ["세미나", "포럼", "설명회", "워크숍", "강연"]),
    ("전시", ["전시", "박람회", "엑스포"]),
]

# 뉴스 검색(Google 뉴스 RSS) 후보. 뉴스 기사가 섞이므로 기본은 끔
USE_NEWS_SEARCH = False
EVENT_SEARCH = [
    "https://news.google.com/rss/search?q=" + urllib.parse.quote(
        "보안 세미나 OR 정보보호 세미나 OR 사이버보안 세미나 OR 보안 컨퍼런스 OR 정보보호 컨퍼런스")
    + "&hl=ko&gl=KR&ceid=KR:ko",
    "https://news.google.com/rss/search?q=" + urllib.parse.quote(
        "보안 교육 모집 OR 사이버보안 교육 모집 OR 정보보호 교육 신청 OR 보안 웨비나 OR 정보보호 설명회")
    + "&hl=ko&gl=KR&ceid=KR:ko",
]

OUT = Path("site")
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.5"}
KST = dt.timezone(dt.timedelta(hours=9))

_KEV_CACHE = None   # KEV 원본 (한 번만 내려받아 재사용)
_NVD_TOTAL = None   # 최근 2일 Critical CVE 전체 건수


# ----------------------------- 유틸 -----------------------------
def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def decode_html(raw):
    for enc in ("utf-8", "cp949"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", "ignore")


def to_epoch(s):
    if not s:
        return 0
    s = s.strip()
    try:
        return int(email.utils.parsedate_to_datetime(s).timestamp())
    except Exception:
        pass
    try:
        d = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=KST)
        return int(d.timestamp())
    except Exception:
        return 0


def clean(s):
    s = html.unescape(s or "")
    s = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def strip_source(title):
    """Google 뉴스 제목 끝의 ' - 언론사' 를 제거"""
    parts = title.rsplit(" - ", 1)
    if len(parts) == 2 and len(parts[1]) <= 20:
        return parts[0].strip()
    return title


def parse_rss(url, source):
    root = ET.fromstring(http_get(url))
    out = []
    for it in root.iter("item"):
        title = clean(it.findtext("title"))
        if not title:
            continue
        pub = it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")
        out.append({
            "src": source,
            "title": title,
            "link": (it.findtext("link") or "").strip(),
            "ts": to_epoch(pub),
            "desc": clean(it.findtext("description") or it.findtext("{http://www.w3.org/2005/Atom}summary") or "")[:400],
        })
    return out


# ----------------------------- 취약점 한글 분류 -----------------------------
ATTACKS = [
    (("remote code execution", "arbitrary code", "code execution", "command injection", "os command",
      "code injection", "deserialization"), "원격 코드 실행", "서버를 원격으로 장악", 1),
    (("authentication bypass", "improper authentication", "missing authentication", "authorization bypass",
      "default credential", "hard-coded", "hardcoded", "auth bypass"), "인증 우회", "로그인 없이 접근", 1),
    (("privilege escalation", "elevation of privilege", "improper privilege", "privilege"),
     "권한 상승", "관리자 권한 탈취", 1),
    (("sql injection",), "SQL 인젝션", "DB 정보 탈취·변조", 1),
    (("xml external entity", "xxe", "server-side request forgery", "ssrf"), "XXE·SSRF", "내부 정보 유출", 2),
    (("path traversal", "directory traversal", "file upload", "arbitrary file", "file read", "file inclusion"),
     "파일 조작·탈취", "서버 파일 열람·유출", 2),
    (("security feature bypass", "bypass"), "보안 기능 우회", "방어 장치 무력화", 2),
    (("buffer overflow", "use after free", "use-after-free", "out-of-bounds", "memory corruption", "heap",
      "type confusion"), "메모리 손상", "코드 실행·장애 유발", 2),
    (("denial of service", "denial-of-service", "resource exhaustion", "crash"),
     "서비스 거부(DoS)", "장비 중단·마비", 3),
    (("cross-site scripting", "xss"), "XSS", "악성 스크립트 실행", 3),
    (("information disclosure", "sensitive information", "information exposure", "information leak", "disclosure"),
     "정보 노출", "민감정보 유출", 3),
]
DEFAULT_ATK = ("기타 취약점", "상세 내용은 원문 확인", 3)

DEFAULT_CAT = "기타 SW·장비"
CATS = [
    (("vpn", "firewall", "adaptive security appliance", "asa", "ftd", "firepower", "fortios", "axgate",
      "pan-os", "sonicwall", "globalprotect", "netscaler", "big-ip", "secure client"), "방화벽·VPN"),
    (("exchange", "mail", "webmail", "zimbra", "roundcube", "postfix", "esa"), "메일 서버"),
    (("chrome", "chromium", "firefox", "edge", "safari", "browser", "webkit"), "웹 브라우저"),
    (("windows", "kernel", "linux", "ubuntu", "android", "ios", "macos", "apple"), "OS·커널"),
    (("wordpress", "php", "apache", "nginx", "tomcat", "iis", "node.js", "openssh", "ssh", "web", "joomla",
      "drupal", "struts", "spring"), "웹·서버 SW"),
    (("sql", "oracle", "mysql", "postgres", "postgresql", "database", "mongodb", "redis"), "데이터베이스"),
    (("router", "switch", "meraki", "access point", "wlc", "camera", "nas", "synology", "qnap", "d-link",
      "dlink", "tp-link", "zyxel"), "네트워크·IoT 장비"),
    (("vmware", "esxi", "vcenter", "hyper-v", "citrix", "kubernetes", "docker", "gitlab", "jenkins", "ibm",
      "sap", "gpustack", "aispera"), "서버·플랫폼"),
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
            if any(k in low for k in keys):
                return label, eff, lvl
    return DEFAULT_ATK


def categorize(text):
    low = (text or "").lower()
    for keys, cat in CATS:
        if any(re.search(r"\b" + re.escape(k) + r"\b", low) for k in keys):
            return cat
    return DEFAULT_CAT


def guess_product(desc):
    try:
        m = re.search(r"(?:vulnerability|flaw|issue|weakness) in (?:the )?(.{4,60}?)"
                      r"(?: (?:of|could|allows|that|which|before|prior|through|version)\b|[,.;(])", desc, re.I)
        if m:
            return m.group(1).strip()
        m = re.match(r"(.{4,40}?)(?: (?:before|prior to|through|version|allows|is|in|up to)\b|[,(])", desc)
        return (m.group(1) if m else desc[:40]).strip()
    except Exception:
        return desc[:40]


def kev_item(v):
    name = v.get("vulnerabilityName", "")
    vendor = v.get("vendorProject", "")
    product = v.get("product", "")
    short = v.get("shortDescription", "")
    atk, eff, lvl = classify(name, short)
    cat = categorize(" ".join([vendor, product, name, short]))
    if cat == DEFAULT_CAT and "cisco" in vendor.lower():
        cat = "Cisco 장비·SW"
    return {
        "cve": v.get("cveID", ""),
        "vendor": vendor,
        "product": product,
        "name": name,
        "added": v.get("dateAdded", ""),
        "due": v.get("dueDate", ""),
        "ransom": v.get("knownRansomwareCampaignUse", "") == "Known",
        "ours": any(k in vendor.lower() for k in OUR_VENDORS),
        "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sol": SOL.get(cat, SOL[DEFAULT_CAT]),
    }


def psirt_item(x):
    desc = x.get("desc", "")
    atk, eff, lvl = classify(x["title"], desc)
    cat = categorize(x["title"])
    if cat == DEFAULT_CAT:
        cat = "Cisco 장비·SW"
    m = re.search(r"(?:Impact Rating|Severity)\W{0,6}(Critical|High|Medium|Low)", desc, re.I)
    sev = SEV_KO.get(m.group(1).capitalize(), "") if m else ""
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)\$", "", x["title"])
    return {"title": title, "link": x.get("link", ""), "ts": x["ts"],
            "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sev": sev}


# ----------------------------- 수집 -----------------------------
def fetch_news():
    items, ok = [], 0
    for name, url in NEWS_FEEDS:
        try:
            items += parse_rss(url, name)
            ok += 1
        except Exception as e:
            print("[실패] 뉴스", name, e)
    if ok == 0:
        raise RuntimeError("모든 뉴스 피드 실패")
    seen, uniq = set(), []
    for it in sorted(items, key=lambda x: x["ts"], reverse=True):
        key = re.sub(r"\W", "", it["title"])[:30]
        if key in seen:
            continue
        seen.add(key)
        it.pop("desc", None)
        uniq.append(it)
    cutoff = time.time() - 48 * 3600
    recent = [x for x in uniq if x["ts"] >= cutoff]
    return (recent if len(recent) >= 12 else uniq)[:30]


def load_kev():
    global _KEV_CACHE
    if _KEV_CACHE is None:
        _KEV_CACHE = json.loads(http_get(KEV_URL, 40).decode("utf-8"))
    return _KEV_CACHE


def fetch_kev():
    data = load_kev()
    vulns = sorted(data.get("vulnerabilities", []),
                   key=lambda v: (v.get("dateAdded", ""), v.get("cveID", "")), reverse=True)[:8]
    return [kev_item(v) for v in vulns]


def fetch_nvd():
    global _NVD_TOTAL
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=2)
    q = urllib.parse.urlencode({
        "cvssV3Severity": "CRITICAL",
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 50,
    })
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
        out.append({"cve": c.get("id", ""), "score": score, "desc": clean(desc)[:110],
                    "atk": atk, "eff": eff, "lvl": lvl, "cat": categorize(desc),
                    "prod": guess_product(clean(desc))})
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
        try:
            out.append(dt.date(int(m.group(1)), int(m.group(2)), int(m.group(3))))
        except ValueError:
            pass
    return out


def event_type(title, given=""):
    if given:
        return given
    for label, keys in EVENT_TYPES:
        if any(k in title for k in keys):
            return label
    return "행사"


def passes(title, need_event):
    low = title.lower()
    if not any(k in low for k in SEC_KW):
        return False
    if any(w in title for w in EXCLUDE_WORDS) or any(w in title for w in PAST_WORDS):
        return False
    if need_event and not (any(w in title for w in EVENT_WORDS) or any(w in title for w in ACTION_WORDS)):
        return False
    return True


def load_registered_events():
    today = dt.datetime.now(KST).date()
    out = []
    if not EVENTS_FILE.exists():
        return out
    try:
        arr = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        print("[경고] events.json 형식 오류:", e)
        return out
    for e in arr:
        try:
            s = dt.date.fromisoformat(str(e["date"]))
            en = dt.date.fromisoformat(str(e.get("end") or e["date"]))
        except Exception as e2:
            print("[경고] events.json 날짜 형식 오류:", e2)
            continue
        if en < today:
            continue
        title = e.get("title", "")
        out.append({"kind": "event", "src": "등록", "type": event_type(title, e.get("type", "")),
                    "date": s.isoformat(), "end": en.isoformat(), "time": e.get("time", ""),
                    "title": title, "place": e.get("place", ""), "link": e.get("link", "")})
    out.sort(key=lambda x: (x["date"], x["title"]))
    return out[:10]


def scrape_site(site):
    page = decode_html(http_get(site["url"], 30))
    today = dt.datetime.now(KST).date()
    out, seen = [], set()
    for m in re.finditer(r"<a\b([^>]*)>(.*?)</a>", page, re.S | re.I):
        attrs, inner = m.group(1), m.group(2)
        if site["require_param"] not in html.unescape(attrs):
            continue
        title = clean(inner)
        if len(title) < 6 or not passes(title, site.get("need_event", True)):
            continue
        key = re.sub(r"\W", "", title)[:30]
        if key in seen:
            continue
        seen.add(key)
        hm = re.search(r"href\s*=\s*[\"']([^\"']+)[\"']", attrs, re.I)
        href = html.unescape(hm.group(1)).strip() if hm else ""
        if not href or href.lower().startswith("javascript") or href.startswith("#"):
            link = site["url"]
        else:
            link = urllib.parse.urljoin(site["url"], href)
            if not link.startswith(site["domain"]):
                link = site["url"]
        ds = find_dates(clean(page[m.end(): m.end() + 400]))
        posted = ds[0] if ds else None
        if posted and (today - posted).days > 60:
            continue
        ts = int(dt.datetime.combine(posted, dt.time(12), KST).timestamp()) if posted else 0
        out.append({"kind": "site", "src": site.get("label", site["name"]), "type": event_type(title),
                    "title": title, "link": link, "ts": ts, "posted": posted.isoformat() if posted else ""})
    return out


def fetch_bexco():
    page = decode_html(http_get(BEXCO_URL, 30))
    today = dt.datetime.now(KST).date()
    out, seen = [], set()
    for blk in re.findall(r"<(?:li|tr)\b.*?</(?:li|tr)>", page, re.S | re.I):
        text = clean(blk)
        ds = find_dates(text)
        if not ds:
            continue
        s = ds[0]
        e = ds[1] if len(ds) > 1 else ds[0]
        if e < s:
            e = s
        if e < today:
            continue
        dm = DATE_RE.search(text)
        head = text[:dm.start()].strip()
        tail = DATE_RE.sub("", text[dm.end():], count=1).replace("~", " ").strip()
        head = re.sub(r"^(?:상세보기|진행중|D-\d+|D-day|이벤트|회의|전시|공연|컨벤션|\s)+", "", head).strip()
        for cat in (" 회의 ", " 이벤트 ", " 전시 ", " 공연 "):
            if cat in head:
                a, b = [p.strip() for p in head.split(cat, 1)]
                if a and b and (a == b or a in b or b in a):
                    head = b if len(b) >= len(a) else a
                break
        if len(head) < 4 or not any(k in head.lower() for k in SEC_KW):
            continue
        if any(w in head for w in EXCLUDE_WORDS):
            continue
        key = re.sub(r"\W", "", head)[:30] + s.isoformat()
        if key in seen:
            continue
        seen.add(key)
        hm = re.search(r"<a\b[^>]*href\s*=\s*[\"']([^\"']+)[\"']", blk, re.I)
        href = html.unescape(hm.group(1)).strip() if hm else ""
        link = BEXCO_URL if (not href or href.lower().startswith("javascript") or href.startswith("#")) \
            else urllib.parse.urljoin(BEXCO_URL, href)
        out.append({"kind": "event", "src": "벡스코", "type": event_type(head), "date": s.isoformat(),
                    "end": e.isoformat(), "time": "", "title": head, "place": "벡스코 " + tail[:30].strip(),
                    "link": link})
    out.sort(key=lambda x: (x["date"], x["title"]))
    return out[:6]


def fetch_event_search():
    found, seen = [], set()
    cutoff = time.time() - 21 * 86400
    for url in EVENT_SEARCH:
        try:
            items = parse_rss(url, "검색")
        except Exception as e:
            print("[실패] 행사 검색", e)
            continue
        for it in items:
            t = strip_source(it["title"])
            if it["ts"] < cutoff or not passes(t, True):
                continue
            key = re.sub(r"\W", "", t)[:30]
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": "search", "type": event_type(t), "title": t,
                          "link": it["link"], "ts": it["ts"]})
    found.sort(key=lambda x: x["ts"], reverse=True)
    return found[:4]


def fetch_events():
    reg = load_registered_events()
    fails, tried = 0, 0

    bex = []
    tried += 1
    try:
        bex = fetch_bexco()
        print("[수집] 벡스코", len(bex), "건")
    except Exception as e:
        fails += 1
        print("[실패] 벡스코", e)

    sites, seen = [], set()
    for site in TARGET_SITES:
        tried += 1
        try:
            got = scrape_site(site)
            print("[수집]", site["name"], len(got), "건")
        except Exception as e:
            fails += 1
            print("[실패]", site["name"], e)
            continue
        for g in got:
            key = re.sub(r"\W", "", g["title"])[:30]
            if key not in seen:
                seen.add(key)
                sites.append(g)
    sites.sort(key=lambda x: x["ts"], reverse=True)

    srch = []
    if USE_NEWS_SEARCH:
        try:
            srch = fetch_event_search()
        except Exception as e:
            print("[실패] 행사 검색", e)

    allv = reg + bex + sites[:12] + srch
    print("행사 합계: 등록", len(reg), "/ 벡스코", len(bex), "/ 기관 게시판", len(sites), "/ 검색", len(srch),
          "/ 수집 실패", fails, "of", tried)
    if not allv and fails > 0:
        raise RuntimeError("행사 수집 실패 (이전 데이터 유지)")
    return allv[:20]


def fetch_weather():
    q = urllib.parse.urlencode({
        "latitude": BUSAN[0], "longitude": BUSAN[1],
        "current": "temperature_2m,weather_code",
        "daily": "weather_code,temperature_2m_max,temperature_2m_min,precipitation_probability_max",
        "timezone": "Asia/Seoul", "forecast_days": 7,
    })
    d = json.loads(http_get("https://api.open-meteo.com/v1/forecast?" + q).decode("utf-8"))
    dd = d["daily"]
    days = []
    for i, t in enumerate(dd["time"]):
        days.append({
            "date": t, "code": dd["weather_code"][i],
            "max": round(dd["temperature_2m_max"][i]), "min": round(dd["temperature_2m_min"][i]),
            "pop": dd["precipitation_probability_max"][i],
        })
    return {"temp": round(d["current"]["temperature_2m"]), "code": d["current"]["weather_code"], "days": days}


def build_stats(psirt, prev_nvd=0):
    kev = _KEV_CACHE
    if not kev:
        raise RuntimeError("KEV 데이터 없음")
    anchor = dt.datetime.now(dt.timezone.utc).date()
    s30 = (anchor - dt.timedelta(days=29)).isoformat()
    s7 = (anchor - dt.timedelta(days=6)).isoformat()
    s1 = (anchor - dt.timedelta(days=1)).isoformat()

    types, total30, new2, ours7_ids = {}, 0, 0, []
    vulns = sorted(kev.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
    for v in vulns:
        a = v.get("dateAdded", "")
        if a < s30:
            break
        if a >= s1:
            new2 += 1
        lab = classify(v.get("vulnerabilityName", ""), v.get("shortDescription", ""))[0]
        if lab == DEFAULT_ATK[0]:
            lab = "기타"
        types[lab] = types.get(lab, 0) + 1
        total30 += 1
        ours = any(k in v.get("vendorProject", "").lower() for k in OUR_VENDORS)
        if ours and a >= s7:
            ours7_ids.append(v.get("cveID", ""))

    now = time.time()
    psirt_hi = any(p.get("sev") in ("치명", "높음") and now - p.get("ts", 0) <= 86400 for p in (psirt or []))
    nvd = _NVD_TOTAL if _NVD_TOTAL is not None else prev_nvd
    score = min(new2, 8) + 3 * min(len(ours7_ids), 2) + (2 if nvd >= 5 else 0) + (3 if psirt_hi else 0)
    level = "경계" if score >= THREAT_HIGH else ("주의" if score >= THREAT_MID else "안정")

    items = sorted([(k, n) for k, n in types.items() if k != "기타"], key=lambda x: -x[1])
    top = items[:4]
    rest = sum(n for _, n in items[4:]) + types.get("기타", 0)
    if rest:
        top.append(("기타", rest))
    return {
        "types": [{"name": k, "n": n} for k, n in top],
        "total30": total30, "new2": new2, "ours7": len(ours7_ids), "ours7_ids": ours7_ids[:3],
        "nvd": nvd, "score": score, "level": level,
    }


def load_prev():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if "/" not in repo:
        return {}
    owner, name = repo.split("/", 1)
    try:
        url = "https://%s.github.io/%s/data.json?%d" % (owner, name, int(time.time()))
        return json.loads(http_get(url, 15).decode("utf-8"))
    except Exception:
        return {}


def main():
    prev = load_prev()
    data = {"generated": int(time.time()), "errors": []}
    jobs = (("news", fetch_news, []), ("kev", fetch_kev, []), ("nvd", fetch_nvd, []),
            ("psirt", fetch_psirt, []), ("events", fetch_events, []), ("weather", fetch_weather, {}))
    for key, fn, empty in jobs:
        try:
            data[key] = fn()
            print("[성공]", key)
        except Exception as e:
            print("[실패]", key, e)
            data["errors"].append(key)
            data[key] = prev.get(key, empty)
    try:
        data["stats"] = build_stats(data.get("psirt", []), (prev.get("stats") or {}).get("nvd", 0))
        print("[성공] stats 위협수준:", data["stats"]["level"], "점수:", data["stats"]["score"])
    except Exception as e:
        print("[실패] stats", e)
        data["errors"].append("stats")
        data["stats"] = prev.get("stats", {})
    
    # 📌 site 폴더가 반드시 생성되도록 보장 (GitHub Actions 배포 오류 방지)
    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    (OUT / "index.html").write_text(INDEX_HTML.replace("__AUTO__", json.dumps(AUTO)), encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    print("완료:", len(data["news"]), "news,", len(data["kev"]), "kev,", len(data["events"]), "events")


# ----------------------------- 화면 (TV 브라우저 호환을 위해 단순 문법 사용) -----------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BEE TECHNOLOGY 보안 전광판</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:100%;background:#050A16;overflow:hidden;font-family:'Noto Sans KR','Malgun Gothic','Apple SD Gothic Neo',sans-serif;color:#E5EEF9}
#board{position:absolute;left:50%;top:50%;width:1080px;height:1920px;transform-origin:center center;
 background:radial-gradient(ellipse at 20% 0%,#0F2A4A 0%,#0A1428 45%,#050A16 100%);
 padding:14px;display:grid;grid-template-rows:116px 66px 160px 310px 290px 180px 180px 1fr 52px 28px;row-gap:10px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:16px 22px;overflow:hidden;position:relative}
.hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.ttl{font-size:26px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;padding-left:12px;border-left:6px solid #22D3EE;line-height:1.1;min-width:0}
.ttl small{font-size:18px;font-weight:500;color:#7C93B2;margin-left:10px}
.pg{display:flex;align-items:center;flex:none;margin-left:10px}
.pb{width:44px;height:38px;border:0;border-radius:10px;background:rgba(34,211,238,.15);color:#22D3EE;font-size:28px;font-weight:900;line-height:36px;cursor:pointer;margin-left:6px}
.pb:hover,.pb:focus{outline:2px solid #22D3EE;outline-offset:1px}
.pd{display:inline-block;margin:0 6px;min-width
