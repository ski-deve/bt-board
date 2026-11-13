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
import math
import os
import re
import ssl
import time
import datetime as dt
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

# ----------------------------- 설정 -----------------------------
NEWS_FEEDS = [
    ("보안뉴스", "https://www.boannews.com/rss/allArticle.xml"),
    ("데일리시큐", "https://www.dailysecu.com/rss/allArticle.xml"),
    ("KISA", "https://kisa.or.kr/rss/402"),  # KISA 보도자료 (공식 RSS 목록: https://www.kisa.or.kr/702)
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BUSAN = (35.1796, 129.0756)
# 기상청 단기예보 인증키 (공공데이터포털). 코드에 직접 적지 말고 환경변수 KMA_API_KEY 로 전달하세요.
#   GitHub: 저장소 Settings > Secrets and variables > Actions 에 KMA_API_KEY 로 등록
# 키가 없거나 호출이 실패하면 자동으로 Open-Meteo 날씨를 사용합니다.
KMA_KEY = os.environ.get("KMA_API_KEY", "").strip()
KMA_BASE = "https://apis.data.go.kr/1360000/VilageFcstInfoService_2.0"
KST = dt.timezone(dt.timedelta(hours=9))
EVENTS_FILE = Path("events.json")

# 위협 수준 (자체 산정 기준이며 국가 공식 경보 단계와 무관합니다)
#   점수 = 신규 악용(2일, 최대 8) + 취급 제품 해당(7일, 건당 3점, 최대 6) + Critical CVE 5건 이상(2점) + Cisco 치명·높음 권고(3점)
THREAT_MID = 5     # 이 점수 이상이면 "주의"
THREAT_HIGH = 10   # 이 점수 이상이면 "경계"

# 자동 넘김 간격(초). 0 이면 끔 (기본: 수동 넘김 - 버튼 또는 좌우 드래그)
AUTO = {"news": 0, "kev": 0, "events": 0, "nvd": 0, "psirt": 0}

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
     "require_param": "idx=", "need_event": True, "lenient_ssl": True},
    {"name": "부산경제진흥원_기업지원사업", "label": "BEPA",
     "url": "https://www.bepa.kr/kor/view.do?no=1505", "domain": "https://www.bepa.kr",
     "require_param": "idx=", "need_event": True, "lenient_ssl": True},
    {"name": "부산과학기술고등교육진흥원_사업", "label": "BISTEP",
     "url": "https://www.bistep.re.kr/board.es?mid=a10301010000&bid=0002", "domain": "https://www.bistep.re.kr",
     "require_param": "nttSn=", "need_event": True, "lenient_ssl": True},
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
def http_get(url, timeout=25, lenient_ssl=False):
    req = urllib.request.Request(url, headers=UA)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except urllib.error.URLError as e:
        # 상대 사이트가 인증서 중간 단계를 빠뜨린 경우에만 (lenient_ssl=True 인 사이트), 검증 없이 한 번 더 시도
        if lenient_ssl and isinstance(getattr(e, "reason", None), ssl.SSLCertVerificationError):
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.read()
        raise


def http_get_retry(url, timeout=60, tries=3, wait=8):
    """느린 서버용: 시간 초과/일시 오류면 잠시 쉬었다가 다시 시도"""
    last = None
    for i in range(tries):
        try:
            return http_get(url, timeout)
        except Exception as e:
            last = e
            print("[재시도]", i + 1, "/", tries, str(e)[:80])
            if i < tries - 1:
                time.sleep(wait * (i + 1))
    raise last


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


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")


def parse_rss(url, source):
    root = ET.fromstring(http_get(url))
    out = []
    for it in root.iter("item"):
        title = clean(it.findtext("title"))
        if not title:
            continue
        pub = it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")
        raw = (it.findtext("description") or "") + " " + title
        out.append({
            "cves": list(dict.fromkeys(CVE_RE.findall(raw))),
            "src": source,
            "title": title,
            "link": (it.findtext("link") or "").strip(),
            "ts": to_epoch(pub),
            "desc": clean(it.findtext("description") or it.findtext("{http://www.w3.org/2005/Atom}summary") or "")[:400],
        })
    return out


# ----------------------------- 취약점 한글 분류 -----------------------------
# 공격 유형: (영어 키워드들, 한글 이름, 한 줄 영향 설명, 위험 등급 1=빨강 2=주황 3=노랑)
# 위에서부터 먼저 일치하는 것이 적용되므로 순서를 바꾸지 마세요.
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

# 대상 분류: (영어 단어들, 분류 이름)
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
# 분류별 우리 취급 솔루션 제안 (영업 포인트)
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
    """제목/설명에서 공격 유형을 찾아 (한글 이름, 영향 설명, 등급) 반환"""
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
    """NVD 영문 설명에서 제품명 부분만 대략 추출"""
    try:
        # "A vulnerability was determined in Linksys EA8100 1.0.3 ..." 형태: 제품명(+모델)만 추출
        m = re.search(r"(?:determined|found|discovered|identified|classified|detected)\s+in\s+(?:the\s+)?"
                      r"([A-Za-z0-9][A-Za-z0-9 ._\-/]{2,50}?)(?=\s+v?\d+(?:\.\d+)+|\s*[,.;(]|\s+(?:up to|through|before|prior|and|of|that|this)\b)", desc)
        if m:
            return m.group(1).strip()
        # "NextScan 1.1.0 through 1.2.0 contains ..." / "XWEB EVO before 5.6.2 ..." 형태
        m = re.match(r"([A-Za-z0-9][A-Za-z0-9 ._\-/]{2,40}?)\s+(?:versions?\s+)?(?:v?\d+(?:\.\d+)+\s+)?(?:through|before|prior to|up to|and earlier)\b", desc)
        if m:
            return m.group(1).strip()
        m = re.search(r"(?:vulnerability|flaw|issue|weakness) in (?:the )?(.{4,60}?)"
                      r"(?: (?:of|could|allows|that|which|before|prior|through|version)\b|[,.;(])", desc, re.I)
        if m:
            r = m.group(1).strip()
            return (r.rsplit(" in ", 1)[-1].strip() if " in " in r else r)
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


def csaf_info(link):
    """Cisco 권고 1건의 공식 CSAF 데이터에서 CVE 번호와 심각도를 가져옴 (실패하면 빈 값)"""
    m = re.search(r"/CiscoSecurityAdvisory/([^/?#]+)", link or "")
    if not m:
        return [], "", None
    aid = m.group(1)
    url = "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/%s/csaf/%s.json" % (aid, aid)
    d = json.loads(http_get(url, 20).decode("utf-8"))
    cves, v3, other = [], [], []
    for v in d.get("vulnerabilities") or []:
        c = (v.get("cve") or "").strip()
        if c and c not in cves:
            cves.append(c)
        for sc in v.get("scores") or []:
            for k, val in sc.items():
                if isinstance(val, dict) and val.get("baseScore") is not None:
                    try:
                        (v3 if "v3" in k or "v4" in k else other).append(float(val["baseScore"]))
                    except (TypeError, ValueError):
                        pass
    sev = (((d.get("document") or {}).get("aggregate_severity")) or {}).get("text", "")
    score = max(v3 or other or [0])
    return cves, sev, (score if score > 0 else None)


def psirt_item(x):
    desc = x.get("desc", "")
    atk, eff, lvl = classify(x["title"], desc)
    cat = categorize(x["title"])
    if cat == DEFAULT_CAT:
        cat = "Cisco 장비·SW"
    m = re.search(r"(?:Impact Rating|Severity)\W{0,6}(Critical|High|Medium|Low)", desc, re.I)
    sev = SEV_KO.get(m.group(1).capitalize(), "") if m else ""
    if not sev:
        sev = SEV_KO.get((x.get("csaf_sev") or "").capitalize(), "")
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)$", "", x["title"])
    return {"title": title, "link": x.get("link", ""), "ts": x["ts"],
            "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sev": sev, "cves": x.get("cves", []), "score": x.get("csaf_score")}


# ----------------------------- 수집: 뉴스 / 취약점 -----------------------------
OBIT_RE = re.compile(r"부고|부음|부친상|모친상|빙부상|빙모상|장인상|장모상|시부상|시모상|조부상|조모상|별세|빈소|발인|영결식|\[\s*訃告\s*\]|訃告")


def is_obit(title):
    """경조사(부고) 기사 여부"""
    return bool(OBIT_RE.search(title or ""))


def fetch_news():
    items, ok = [], 0
    for name, url in NEWS_FEEDS:
        try:
            items += [x for x in parse_rss(url, name) if not is_obit(x["title"])]
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
    data = json.loads(http_get_retry("https://services.nvd.nist.gov/rest/json/cves/2.0?" + q, 60, 3, 8).decode("utf-8"))
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
    return out[:6]


def fetch_psirt():
    items = parse_rss(CISCO_PSIRT, "Cisco")
    items.sort(key=lambda x: x["ts"], reverse=True)
    items = items[:6]
    for x in items:
        try:
            cves, sev, score = csaf_info(x.get("link", ""))
            x["cves"] = list(dict.fromkeys(x.get("cves", []) + cves))
            x["csaf_sev"] = sev
            x["csaf_score"] = score
        except Exception as e:
            print("[경고] Cisco CSAF 실패", x.get("link", "")[-40:], str(e)[:60])
    return [psirt_item(x) for x in items]


# ----------------------------- 수집: 국내 보안행사 -----------------------------
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
    """보안 키워드가 있고, 입찰·채용·종료 공고가 아니며, (필요하면) 행사 단어가 있어야 통과"""
    low = title.lower()
    if not any(k in low for k in SEC_KW):
        return False
    if any(w in title for w in EXCLUDE_WORDS) or any(w in title for w in PAST_WORDS):
        return False
    if need_event and not (any(w in title for w in EVENT_WORDS) or any(w in title for w in ACTION_WORDS)):
        return False
    return True


def load_registered_events():
    """events.json 에 직접 등록한 확정 일정 (지난 행사는 숨김)"""
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
        except Exception:
            print("[경고] events.json 날짜 형식 오류:", e)
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
    """게시판 목록 HTML 에서 게시글 링크를 찾아 보안 관련 항목만 추출 (사이트별 구조를 몰라도 동작하는 범용 방식)"""
    page = decode_html(http_get(site["url"], 30, site.get("lenient_ssl", False)))
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
    """벡스코 행사일정 목록에서 보안 관련 행사만 추출 (날짜 범위 포함)"""
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
    """(선택) 검색 RSS 에서 교육·세미나·컨퍼런스 모집·공지 기사만 후보로 모음"""
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


# ----------------------------- 수집: 날씨 -----------------------------
def _fetch_weather_openmeteo():
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


def kma_grid(lat, lon):
    """위경도 -> 기상청 격자(nx, ny) (람베르트 정형도법, 기상청 공식 변환식)"""
    RE, GRID, SLAT1, SLAT2, OLON, OLAT, XO, YO = 6371.00877, 5.0, 30.0, 60.0, 126.0, 38.0, 43, 136
    D = math.pi / 180.0
    re = RE / GRID
    slat1, slat2, olon, olat = SLAT1 * D, SLAT2 * D, OLON * D, OLAT * D
    sn = math.tan(math.pi * 0.25 + slat2 * 0.5) / math.tan(math.pi * 0.25 + slat1 * 0.5)
    sn = math.log(math.cos(slat1) / math.cos(slat2)) / math.log(sn)
    sf = math.tan(math.pi * 0.25 + slat1 * 0.5)
    sf = math.pow(sf, sn) * math.cos(slat1) / sn
    ro = math.tan(math.pi * 0.25 + olat * 0.5)
    ro = re * sf / math.pow(ro, sn)
    ra = math.tan(math.pi * 0.25 + lat * D * 0.5)
    ra = re * sf / math.pow(ra, sn)
    theta = lon * D - olon
    if theta > math.pi:
        theta -= 2.0 * math.pi
    if theta < -math.pi:
        theta += 2.0 * math.pi
    theta *= sn
    return int(ra * math.sin(theta) + XO + 0.5), int(ro - ra * math.cos(theta) + YO + 0.5)


def kma_call(op, base_date, base_time, nx, ny, rows=1000):
    """기상청 단기예보 API 호출 -> item 목록 (여러 페이지면 모두 합침)"""
    key = urllib.parse.unquote(KMA_KEY)
    items, page = [], 1
    while True:
        q = urllib.parse.urlencode({
            "serviceKey": key, "pageNo": page, "numOfRows": rows, "dataType": "JSON",
            "base_date": base_date, "base_time": base_time, "nx": nx, "ny": ny})
        d = json.loads(http_get(KMA_BASE + "/" + op + "?" + q).decode("utf-8"))
        r = d["response"]
        if r["header"]["resultCode"] != "00":
            raise RuntimeError("기상청 응답 오류 " + str(r["header"]["resultCode"]) + " " + str(r["header"].get("resultMsg", "")))
        body = r["body"]
        it = (body.get("items") or {}).get("item") or []
        items.extend(it if isinstance(it, list) else [it])
        if page * rows >= int(body.get("totalCount") or 0):
            return items
        page += 1


def kma_code(sky, pty):
    """기상청 하늘상태/강수형태 -> 화면 아이콘 코드 (WMO 코드 체계에 맞춤)"""
    if pty in (1, 2, 4, 5, 6):
        return 61          # 비 (비/눈·소나기·빗방울 포함)
    if pty in (3, 7):
        return 71          # 눈 (눈날림 포함)
    return {1: 0, 3: 2, 4: 3}.get(sky, 0)   # 맑음 / 구름많음 / 흐림


def _fetch_weather_kma():
    nx, ny = kma_grid(BUSAN[0], BUSAN[1])
    now = dt.datetime.now(KST)
    # 현재 기온/강수: 초단기실황 (매시 정각 자료, 약 40분 뒤 안정적으로 제공)
    nb = now - dt.timedelta(minutes=40)
    ncst = kma_call("getUltraSrtNcst", nb.strftime("%Y%m%d"), nb.strftime("%H00"), nx, ny)
    obs = {i["category"]: i["obsrValue"] for i in ncst}
    temp = round(float(obs["T1H"]))
    pty_now = int(float(obs.get("PTY", 0)))
    # 일별 최고/최저/강수확률: 단기예보 (당일 02시 발표분 = 오늘 최저·최고가 모두 포함, 02:15 이전엔 전날 23시 발표분)
    if now.hour * 60 + now.minute >= 2 * 60 + 15:
        fb, ft = now, "0200"
    else:
        fb, ft = now - dt.timedelta(days=1), "2300"
    fc = kma_call("getVilageFcst", fb.strftime("%Y%m%d"), ft, nx, ny)
    byday = {}
    for i in fc:
        byday.setdefault(i["fcstDate"], {}).setdefault(i["category"], []).append((i["fcstTime"], i["fcstValue"]))
    days = []
    for date in sorted(byday):
        c = byday[date]
        tmp = [float(v) for _, v in c.get("TMP", [])]
        tmn = [float(v) for _, v in c.get("TMN", [])] or tmp
        tmx = [float(v) for _, v in c.get("TMX", [])] or tmp
        if not tmn or not tmx:
            continue
        pop = max([int(float(v)) for _, v in c.get("POP", [])] or [0])
        day = lambda lst: [int(float(v)) for t, v in lst if "06" <= t[:2] <= "21"]   # 낮 시간대(06~21시)
        ptys = [p for p in day(c.get("PTY", [])) if p > 0]
        if ptys:
            code = kma_code(1, max(set(ptys), key=ptys.count))
        else:
            sk = day(c.get("SKY", [])) or [1]
            code = kma_code(max(set(sk), key=lambda x: (sk.count(x), x)), 0)
        d = dt.date(int(date[:4]), int(date[4:6]), int(date[6:]))
        days.append({"date": d.isoformat(), "code": code, "max": round(max(tmx)), "min": round(min(tmn)), "pop": pop})
    if not days:
        raise RuntimeError("기상청 단기예보 데이터 없음")
    # 현재 아이콘: 실황 강수가 있으면 그 값, 없으면 현재 시각에 가장 가까운 예보의 하늘상태
    today = now.strftime("%Y%m%d")
    skies = [(abs(int(t[:2]) - now.hour), int(float(v))) for t, v in byday.get(today, {}).get("SKY", [])]
    sky_now = min(skies)[1] if skies else 1
    code_now = kma_code(sky_now, pty_now) if pty_now else kma_code(sky_now, 0)
    return {"temp": temp, "code": code_now, "days": days}


def fetch_weather():
    """기상청 값을 우선 사용. 기상청이 주지 않는 먼 날짜(3일 이후)는 Open-Meteo 로 채워 7일을 유지."""
    om = None
    try:
        om = _fetch_weather_openmeteo()
    except Exception as e:
        print("[경고] Open-Meteo 날씨 실패:", e)
    if not KMA_KEY:
        print("[안내] KMA_API_KEY 가 비어 있어 Open-Meteo 날씨를 사용합니다 (시크릿 이름/workflow env 확인)")
    if KMA_KEY:
        try:
            k = _fetch_weather_kma()
            print("[안내] 기상청 날씨 적용 (3일 이후는 Open-Meteo)")
            if not om:
                return dict(k, src="KMA")
            kd = {d["date"]: d for d in k["days"]}
            days = [kd.get(d["date"], d) for d in om["days"]]
            return {"temp": k["temp"], "code": k["code"], "days": days, "src": "KMA"}
        except Exception as e:
            print("[경고] 기상청 날씨 실패 -> Open-Meteo 로 대체:", e)
    if om:
        return dict(om, src="Open-Meteo")
    raise RuntimeError("날씨 수집 실패")


# ----------------------------- 통계 (위협 수준 / 30일 공격 유형) -----------------------------
def build_stats(psirt, prev_nvd=0):
    kev = _KEV_CACHE
    if not kev:
        raise RuntimeError("KEV 데이터 없음")
    # CISA 등재일은 미국 기준이라 UTC 날짜를 기준으로 계산
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


# ----------------------------- 실행 -----------------------------
def load_prev():
    """수집 실패 시 직전 data.json 을 재사용 (배포된 Pages 에서 가져옴)"""
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
    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    # AUTO 설정을 화면(JS)에 전달 (이 값이 없으면 화면 스크립트가 멈춰 빈 화면이 됩니다)
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
 padding:14px;display:grid;grid-template-rows:106px 62px 160px 324px 274px 198px 198px 170px 1fr 44px 26px;row-gap:8px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:16px 22px;overflow:hidden;position:relative}
.hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.ttl{font-size:26px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;padding-left:12px;border-left:6px solid #22D3EE;line-height:1.1;min-width:0}
.ttl small{font-size:18px;font-weight:500;color:#93A9C6;margin-left:10px}
.pg{display:flex;align-items:center;flex:none;margin-left:10px}
.pb{width:44px;height:38px;border:0;border-radius:10px;background:rgba(34,211,238,.15);color:#22D3EE;font-size:28px;font-weight:900;line-height:36px;cursor:pointer;margin-left:6px}
.pb:hover,.pb:focus{outline:2px solid #22D3EE;outline-offset:1px}
.pd{display:inline-block;margin:0 6px;min-width:44px;text-align:center;font-size:20px;font-weight:700;color:#93A9C6}
.fade{transition:opacity .25s ease;min-height:0}
.fade.out{opacity:0}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
/* 헤더 */
#head{display:grid;grid-template-columns:1fr auto;align-items:center;padding:0 10px}
.brand{display:flex;align-items:center}
.brand svg{margin-right:16px}
.brand b{font-size:40px;font-weight:900;letter-spacing:-1px;display:block;line-height:1.1}
.brand span{font-size:20px;color:#93A9C6}
.clock{text-align:right}
#clock{font-size:60px;font-weight:900;color:#22D3EE;line-height:60px;letter-spacing:-2px}
#date{font-size:22px;font-weight:700;line-height:28px}
/* 상태 바 */
#status{display:flex;align-items:center;padding:6px 18px}
.chip{display:flex;align-items:center;padding:3px 22px 3px 16px;border-radius:999px;margin-right:22px;white-space:nowrap;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.06)}
.chip .cd{display:inline-block;width:14px;height:14px;border-radius:50%;margin-right:12px;animation:blink 1.6s infinite}
.chip .cl{font-size:17px;font-weight:500;letter-spacing:1px;color:#A9C1DE;margin-right:12px}
.chip b{font-size:30px;font-weight:900;line-height:1.1;letter-spacing:1px}
.chip.lv0{background:linear-gradient(135deg,rgba(52,211,153,.30),rgba(52,211,153,.06));border-color:rgba(52,211,153,.65);box-shadow:0 0 18px rgba(52,211,153,.28),inset 0 0 12px rgba(52,211,153,.12)}
.chip.lv0 .cd{background:#34D399;box-shadow:0 0 10px #34D399}.chip.lv0 b{color:#6EF0BC}
.chip.lv1{background:linear-gradient(135deg,rgba(250,204,21,.30),rgba(250,204,21,.06));border-color:rgba(250,204,21,.65);box-shadow:0 0 18px rgba(250,204,21,.28),inset 0 0 12px rgba(250,204,21,.12)}
.chip.lv1 .cd{background:#FACC15;box-shadow:0 0 10px #FACC15}.chip.lv1 b{color:#FDE047}
.chip.lv2{background:linear-gradient(135deg,rgba(249,115,22,.34),rgba(249,115,22,.08));border-color:rgba(249,115,22,.7);box-shadow:0 0 18px rgba(249,115,22,.32),inset 0 0 12px rgba(249,115,22,.14)}
.chip.lv2 .cd{background:#F97316;box-shadow:0 0 10px #F97316}.chip.lv2 b{color:#FDBA74}
#stats{display:flex;flex:1;justify-content:space-between}
.st{display:flex;align-items:baseline;white-space:nowrap}
.st .lb{font-size:17px;color:#9FB4CE;margin-right:8px}
.st b{font-size:38px;font-weight:900;color:#22D3EE;line-height:1}
.st em{font-style:normal;font-size:17px;color:#9FB4CE;margin-left:3px}
.st .cid{font-family:Consolas,monospace;font-size:15px;color:#F97316;margin-left:8px}
/* 날씨 */
#wx{display:grid;grid-template-columns:270px 1fr;column-gap:18px;padding:12px 18px}
.now{border-right:1px solid rgba(34,211,238,.18);padding-right:14px}
.now .big{font-size:56px;font-weight:900;line-height:1}
.now .cond{font-size:22px;font-weight:700;color:#A9C1DE;line-height:28px}
.week{display:grid;grid-template-columns:repeat(7,1fr);column-gap:8px}
.day{text-align:center;border-radius:14px;padding:4px 2px;background:rgba(255,255,255,.04)}
.day.today{border:2px solid #22D3EE;background:rgba(34,211,238,.1)}
.day.rain{background:rgba(59,130,246,.22)}
.day .dn{font-size:20px;font-weight:700;line-height:24px}
.day .dd{font-size:14px;color:#93A9C6;line-height:16px}
.day .tt{font-size:20px;font-weight:700;line-height:24px}
.day .tt i{font-style:normal;color:#93A9C6;font-weight:500}
.day .pp{font-size:15px;color:#60A5FA;line-height:18px}
/* 뉴스 행 */
.row{display:grid;grid-template-columns:100px 1fr 80px;column-gap:12px;align-items:center;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:0}
.src{font-size:17px;font-weight:700;text-align:center;border-radius:8px;padding:4px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.t{font-size:25px;font-weight:700;line-height:1.28;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ago{font-size:17px;color:#93A9C6;text-align:right}
/* 긴급 취약점 */
.kev{display:grid;grid-template-columns:215px 1fr 120px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.kev:last-child{border-bottom:0}
.cve{font-family:Consolas,monospace;font-size:23px;font-weight:700;color:#22D3EE}
.kev .a{font-size:24px;font-weight:700;line-height:30px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.kev .b{font-size:19px;line-height:24px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.due{font-size:17px;text-align:right;color:#F97316;font-weight:700}
.tag{display:inline-block;font-size:15px;font-weight:900;padding:1px 8px;border-radius:6px;margin-right:8px;vertical-align:middle}
.tag.our{background:#F97316;color:#111}
.tag.rw{background:#EF4444;color:#fff}
.atk{display:inline-block;font-size:17px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:8px;vertical-align:middle;line-height:22px}
.l1{background:#EF4444;color:#fff}.l2{background:#F97316;color:#111}.l3{background:#FACC15;color:#111}
.sol{color:#22D3EE;font-weight:700}
/* 두 칸 */
.vr{display:grid;grid-template-columns:215px minmax(0,1fr) 120px;column-gap:12px;align-items:center;padding:5px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.vr:last-child{border-bottom:0}
.vr .a{font-size:24px;font-weight:700;line-height:28px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vr .b{font-size:19px;line-height:24px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vr .cve{line-height:28px}
.vr .cv2{font-family:Consolas,monospace;font-size:21px;font-weight:700;color:#22D3EE;line-height:25px;white-space:nowrap}
.vr .cn{font-size:16px;line-height:22px;color:#93A9C6;white-space:nowrap}
.vr .sc{text-align:right;font-size:30px;font-weight:900;line-height:30px;font-variant-numeric:tabular-nums}
.vr .sc small{display:block;font-size:14px;line-height:16px;font-weight:500;color:#93A9C6}
.vr .sc.s9{color:#F87171}.vr .sc.s7{color:#FB923C}.vr .sc.s4{color:#FACC15}
.vr.p{grid-template-columns:215px minmax(0,1fr) 150px}
.vr .ag{text-align:right;font-size:18px;color:#93A9C6;font-weight:700}
.mini{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:20px;line-height:26px}
.mini:last-child{border-bottom:0}
.mini b{display:inline-block;min-width:54px;text-align:center;border-radius:6px;margin-right:8px;padding:0 6px;font-size:19px}
.m1{display:flex;align-items:center;white-space:nowrap;overflow:hidden;line-height:28px}
.m1 .atk{margin-right:8px;flex:none}
.m1 .cv{font-family:Consolas,monospace;font-size:20px;font-weight:700;color:#22D3EE;margin-right:10px;flex:none}
.m1 .pr{font-size:18px;color:#9FB4CE;overflow:hidden;text-overflow:ellipsis;min-width:0}
.m1 .ef{font-size:20px;font-weight:700;color:#E5EEF9;overflow:hidden;text-overflow:ellipsis;min-width:0}
.m2{font-size:19px;line-height:26px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.m2 i{font-style:normal;color:#93A9C6}
.sc9{background:#EF4444;color:#fff}.sc7{background:#F97316;color:#111}
.empty{color:#93A9C6;font-size:20px;padding:10px 0}
/* 차트 */
#chart{display:grid;grid-template-columns:1fr;padding:12px 22px}
.dn2{display:flex;align-items:center;height:104px}
.dnw{position:relative;width:104px;height:104px;margin-right:26px;flex:none}
.dnc{position:absolute;left:0;top:0;width:104px;height:104px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.dnc b{font-size:30px;font-weight:900;line-height:1}
.dnc span{font-size:13px;color:#93A9C6}
.lgs{display:grid;grid-template-columns:1fr 1fr;column-gap:26px;row-gap:6px;flex:1}
.lg{font-size:19px;line-height:24px;white-space:nowrap;display:flex;align-items:center}
.lg i{width:14px;height:14px;border-radius:4px;margin-right:9px;flex:none}
.lg b{margin-left:auto;color:#22D3EE;font-size:20px}
/* 국내 보안행사 */
.ev{display:grid;grid-template-columns:1fr 110px;column-gap:14px;align-items:center;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.ev:last-child{border-bottom:0}
.evl{display:flex;align-items:center;margin-bottom:0}
.dt{font-size:20px;font-weight:900;color:#22D3EE;white-space:nowrap;margin-right:10px}
.tt2{font-size:23px;font-weight:700;line-height:28px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pl{font-size:17px;line-height:20px;color:#93A9C6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.evm{min-width:0}
.bd{font-size:18px;font-weight:900;text-align:center;border-radius:8px;padding:4px 0;background:rgba(34,211,238,.15);color:#22D3EE;white-space:nowrap}
.bd.hot{background:#EF4444;color:#fff}
.bd.soon{background:#F97316;color:#111}
.bd.nw{background:rgba(255,255,255,.08);color:#9FB4CE;font-weight:500;font-size:16px}
.tg{display:inline-block;font-size:15px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:8px;vertical-align:middle;white-space:nowrap}
.tgE{background:#34D399;color:#04281c}
.tgS{background:#F97316;color:#111}
.tgN{background:rgba(34,211,238,.2);color:#22D3EE}
/* 티커 */
#ticker{padding:0 18px;display:flex;align-items:center;overflow:hidden}
.live{font-size:18px;font-weight:900;color:#22D3EE;margin-right:16px;white-space:nowrap;display:flex;align-items:center}
.live i{display:inline-block;width:12px;height:12px;border-radius:50%;background:#34D399;margin-right:8px;animation:blink 1s infinite}
#tkmask{flex:1;overflow:hidden;white-space:nowrap}
#tk{display:inline-block;white-space:nowrap;will-change:transform}
@keyframes tkscroll{from{transform:translateX(0)}to{transform:translateX(-50%)}}
.ti{display:inline-block;font-size:24px;font-weight:700;margin-right:56px}
.tg2{display:inline-block;font-size:16px;font-weight:900;padding:1px 9px;border-radius:6px;margin-right:10px;vertical-align:middle}
.tgC{background:#F97316;color:#111}
/* 링크 */
a.lk{color:inherit;text-decoration:none;cursor:pointer}
a.mini{display:block}
a.lk:hover,a.lk:focus{outline:2px solid #22D3EE;outline-offset:2px;border-radius:8px;background:rgba(34,211,238,.08)}
#foot{display:flex;justify-content:space-between;align-items:center;font-size:18px;color:#93A9C6;padding:0 10px}
#foot .bad{color:#FACC15;font-weight:900}
.pulse{display:inline-block;width:10px;height:10px;border-radius:50%;background:#34D399;margin-right:8px;animation:blink 2s infinite}
</style>
</head>
<body>
<div id="board">
  <div id="head">
    <div class="brand">
      <svg width="370" height="100" viewBox="0 0 370 100">
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
      <div style="margin-left:22px"><b style="font-size:42px">오늘의 보안 브리핑</b></div>
    </div>
    <div class="clock"><div id="clock">--:--</div><div id="date"></div></div>
  </div>

  <div id="status" class="panel">
    <div id="chip" class="chip lv0">위협 수준<b>-</b><small>자체 산정</small></div>
    <div id="stats">
      <div class="st"><span class="lb">신규 악용(2일)</span><b id="c1">0</b><em>건</em></div>
      <div class="st"><span class="lb">Critical CVE(2일)</span><b id="c2">0</b><em>건</em></div>
      <div class="st"><span class="lb">취급 제품(7일)</span><b id="c3">0</b><em>건</em><span class="cid" id="c3id"></span></div>
    </div>
  </div>

  <div id="wx" class="panel"></div>

  <div class="panel">
    <div class="hd"><div class="ttl">오늘의 보안뉴스<small>어제·오늘</small></div>
      <div class="pg"><button class="pb" onclick="nav('news',-1)">&lsaquo;</button><span class="pd" id="d-news"></span><button class="pb" onclick="nav('news',1)">&rsaquo;</button></div></div>
    <div id="news" class="fade"></div>
  </div>

  <div class="panel">
    <div class="hd"><div class="ttl">긴급 취약점<small>실제 공격에 악용 중 · 위험 유형과 우리 대응 솔루션</small></div>
      <div class="pg"><button class="pb" onclick="nav('kev',-1)">&lsaquo;</button><span class="pd" id="d-kev"></span><button class="pb" onclick="nav('kev',1)">&rsaquo;</button></div></div>
    <div id="kev" class="fade"></div>
  </div>

  <div class="panel">
    <div class="hd"><div class="ttl">신규 Critical CVE<small>NVD · 최근 2일 · CVSS 9.0 이상</small></div>
      <div class="pg"><button class="pb" onclick="nav('nvd',-1)">&lsaquo;</button><span class="pd" id="d-nvd"></span><button class="pb" onclick="nav('nvd',1)">&rsaquo;</button></div></div>
    <div id="nvd" class="fade"></div>
  </div>

  <div class="panel">
    <div class="hd"><div class="ttl">Cisco 보안 권고<small>PSIRT · 최신 권고</small></div>
      <div class="pg"><button class="pb" onclick="nav('psirt',-1)">&lsaquo;</button><span class="pd" id="d-psirt"></span><button class="pb" onclick="nav('psirt',1)">&rsaquo;</button></div></div>
    <div id="psirt" class="fade"></div>
  </div>

  <div id="chart" class="panel">
    <div class="hd" style="margin-bottom:4px"><div class="ttl">공격 유형 비율<small>CISA 악용 취약점 · 최근 30일</small></div></div>
    <div id="donut"></div>
  </div>

  <div class="panel">
    <div class="hd"><div class="ttl">국내 보안 행사<small>교육·세미나·컨퍼런스 · 벡스코·부산 기관</small></div>
      <div class="pg"><button class="pb" onclick="nav('events',-1)">&lsaquo;</button><span class="pd" id="d-events"></span><button class="pb" onclick="nav('events',1)">&rsaquo;</button></div></div>
    <div id="events" class="fade"></div>
  </div>

  <div id="ticker" class="panel"><span class="live"><i></i>LIVE</span><div id="tkmask"><div id="tk"></div></div></div>

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
/* 링크가 있으면 새 탭으로 열리는 <a>, 없으면 일반 <div> */
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

/* 날씨 아이콘 */
function kind(c){if(c<=1)return 'sun';if(c==2)return 'part';if(c==3)return 'cloud';if(c==45||c==48)return 'fog';
 if((c>=71&&c<=77)||c==85||c==86)return 'snow';return 'rain'}
function label(c){var k=kind(c);return {sun:'맑음',part:'구름많음',cloud:'흐림',fog:'안개',snow:'눈',rain:c>=95?'뇌우':'비'}[k]}
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
 var h='<div class="now"><div class="ttl" style="margin-bottom:2px">부산 날씨</div><div style="display:flex;align-items:center">'+ico(w.code,52)+'<div class="big" style="margin-left:6px">'+w.temp+'°</div></div><div class="cond">'+label(w.code)+'<br>최고 '+w.days[0].max+'° / 최저 '+w.days[0].min+'°</div></div><div class="week">';
 for(var i=0;i<w.days.length;i++){var d=w.days[i],dt=new Date(d.date+'T00:00:00'),rain=kind(d.code)=='rain'||kind(d.code)=='snow';
  h+='<div class="day'+(d.date==ts?' today':'')+(rain?' rain':'')+'"><div class="dn">'+(d.date==ts?'오늘':DAYS[dt.getDay()])+'</div><div class="dd">'+pad(dt.getMonth()+1)+'/'+pad(dt.getDate())+'</div>'+ico(d.code,38)+'<div class="tt">'+d.max+'° <i>'+d.min+'°</i></div><div class="pp">강수 '+d.pop+'%</div></div>'}
 $('wx').innerHTML=h+'</div>'}

/* ---------- 수동/자동 넘김 패널 (뉴스 · 긴급 취약점 · 국내 행사) ---------- */
var LIST={news:[],kev:[],events:[],nvd:[],psirt:[]};
var PER={news:3,kev:3,events:2,nvd:2,psirt:2};
var MAXP={news:4,kev:3,events:6,nvd:3,psirt:3};
var PAGE={news:0,kev:0,events:0,nvd:0,psirt:0};
var EMPTY={
 news:'<div class="empty">뉴스 데이터 없음</div>',
 kev:'<div class="empty">KEV 데이터 없음</div>',
 nvd:'<div class="empty">최근 2일간 신규 Critical 없음</div>',
 psirt:'<div class="empty">Cisco 권고 데이터 없음</div>',
 events:'<div class="empty">표시할 국내 보안 행사가 아직 없습니다 (events.json 에 직접 등록할 수 있습니다)</div>'};
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
 events:evHtml,
 nvd:function(v){return A('vr',NVD+v.cve,'<div class=\"cve\">'+esc(v.cve)+'</div><div><div class=\"a\"><span class=\"atk l'+(v.lvl||3)+'\">'+esc(v.atk)+'</span>'+esc(v.prod)+'</div><div class=\"b\">'+esc(v.cat)+' · '+esc(v.eff)+'</div></div><div class=\"sc '+(v.score>=9?'s9':'s7')+'\">'+Number(v.score).toFixed(1)+'<small>CVSS</small></div>')},
 psirt:function(p){var c=p.cves||[],cl;
  if(!c.length){cl='<div class=\"cn\">CVE 번호 없음</div>'}
  else if(c.length<=2){cl=c.map(function(x){return '<div class=\"cv2\">'+esc(x)+'</div>'}).join('')}
  else{cl='<div class=\"cv2\">'+esc(c[0])+'</div><div class=\"cn\">외 '+(c.length-1)+'건 더</div>'}
  return A('vr p',p.link,'<div>'+cl+'</div><div><div class=\"a\"><span class=\"atk l'+(p.lvl||3)+'\">'+esc(p.atk)+'</span>'+(p.sev?'<span class=\"atk '+(p.sev=='치명'||p.sev=='높음'?'l1':'l3')+'\">'+esc(p.sev)+'</span>':'')+esc(p.eff)+'</div><div class=\"b\">'+esc(p.title)+'</div></div>'+(p.score?'<div class=\"sc '+(p.score>=9?'s9':(p.score>=7?'s7':'s4'))+'\">'+Number(p.score).toFixed(1)+'<small>CVSS · '+ago(p.ts)+'</small></div>':'<div class=\"ag\">'+ago(p.ts)+'</div>'))}
};
function pages(name){return Math.max(1,Math.min(MAXP[name],Math.ceil(LIST[name].length/PER[name])))}
function paint(name){
 var n=pages(name);if(PAGE[name]>=n)PAGE[name]=0;
 var s=PAGE[name]*PER[name],items=LIST[name].slice(s,s+PER[name]),h='',i;
 for(i=0;i<items.length;i++)h+=RENDER[name](items[i]);
 $(name).innerHTML=h||EMPTY[name];
 var dd='';if(n>1){dd=(PAGE[name]+1)+' / '+n}
 $('d-'+name).textContent=dd}
function nav(name,dir){
 var n=pages(name);if(n<2)return;
 PAGE[name]=(PAGE[name]+dir+n)%n;
 var el=$(name);el.className='fade out';
 setTimeout(function(){paint(name);el.className='fade'},220)}
function bindSwipe(name){
 var el=$(name),sx=0,sy=0,drag=false;
 el.addEventListener('pointerdown',function(e){sx=e.clientX;sy=e.clientY;drag=true});
 el.addEventListener('pointerup',function(e){
  if(!drag)return;drag=false;
  var dx=e.clientX-sx,dy=e.clientY-sy;
  if(Math.abs(dx)>60&&Math.abs(dx)>Math.abs(dy)*1.5){SUPPRESS=Date.now()+400;nav(name,dx<0?1:-1)}});
 el.addEventListener('click',function(e){if(Date.now()<SUPPRESS){e.preventDefault();e.stopPropagation()}},true)}
['news','kev','events','nvd','psirt'].forEach(function(n){
 bindSwipe(n);
 if(AUTO[n]>0)setInterval(function(){nav(n,1)},AUTO[n]*1000)});

/* ---------- 상태 바 ---------- */
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
 $('chip').innerHTML='<i class="cd"></i><span class="cl">위협 수준</span><b>'+esc(st.level||'-')+'</b>';
 countTo($('c1'),st.new2);countTo($('c2'),st.nvd);countTo($('c3'),st.ours7);
 $('c3id').textContent=(st.ours7_ids||[]).join(', ')}

/* ---------- 도넛 차트 (30일 공격 유형) ---------- */
var TSIG='',COLS=['#EF4444','#F97316','#FACC15','#22D3EE','#64748B'];
function renderDonut(st){
 var sig=JSON.stringify(st&&st.types);
 if(sig==TSIG)return;TSIG=sig;
 var ty=(st&&st.types)||[],t=0,i;
 for(i=0;i<ty.length;i++)t+=ty[i].n;
 if(!t){$('donut').innerHTML='<div class="empty">데이터 없음</div>';return}
 var C=2*Math.PI*40,cum=0,segs='',lg='';
 for(i=0;i<ty.length;i++){
  var len=C*ty[i].n/t,col=COLS[i%COLS.length];
  segs+='<circle cx="52" cy="52" r="40" fill="none" stroke="'+col+'" stroke-width="14" transform="rotate(-90 52 52)" style="stroke-dasharray:0 '+C+';transition:stroke-dasharray 1s ease" stroke-dashoffset="'+(-cum)+'" data-d="'+len+' '+(C-len)+'"/>';
  cum+=len;
  lg+='<div class="lg"><i style="background:'+col+'"></i>'+esc(ty[i].name)+'<b>'+ty[i].n+'건</b></div>'}
 $('donut').innerHTML='<div class="dn2"><div class="dnw"><svg width="104" height="104" viewBox="0 0 104 104"><circle cx="52" cy="52" r="40" fill="none" stroke="rgba(255,255,255,.08)" stroke-width="14"/>'+segs+'</svg><div class="dnc"><b>'+t+'</b><span>30일 합계</span></div></div><div class="lgs">'+lg+'</div></div>';
 setTimeout(function(){
  var cs=$('donut').getElementsByTagName('circle'),k;
  for(k=0;k<cs.length;k++){var dd=cs[k].getAttribute('data-d');if(dd)cs[k].style.strokeDasharray=dd}
 },80)}

/* ---------- 하단 티커 ---------- */
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
 LIST.kev=(d.kev||[]).slice(0,8);
 LIST.events=(d.events||[]).slice(0,12);
 paint('news');paint('kev');paint('events');

 LIST.nvd=(d.nvd||[]).slice(0,6);
 LIST.psirt=(d.psirt||[]).slice(0,6);
 paint('nvd');paint('psirt');

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
setTimeout(function(){location.reload()},6*3600*1000); /* 6시간마다 전체 새로고침 (TV 브라우저 멈춤 방지) */
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
