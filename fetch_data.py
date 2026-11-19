#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
비테크놀로지 보안 전광판 - 수집기 + 화면 생성기 (GitHub Actions 용)

실행하면 site/ 폴더에 파일을 만듭니다.
  site/data.json   : 보안뉴스 / CISA KEV / NVD(CVSS 8.0 이상, 주요 SW 7.0 이상) / Cisco 권고 /
                     KISA 보안공지 / 국내 보안행사 / 부산·서울 날씨 / 통계
  site/index.html  : 1080x1920 세로 전광판 화면 (data.json 을 60초마다 다시 읽음)

국내 보안행사 (세 곳에서 수집)
  1) events.json 에 직접 등록한 확정 일정 (날짜가 지나면 자동 숨김)
     [{"date":"2026-12-03","end":"2026-12-03","time":"14:00","title":"행사명","place":"장소","link":"https://...","type":"교육"}]
     end, time, place, link, type 은 생략 가능
  2) 벡스코 행사일정 중 IT·AI·보안 관련 행사
  3) TARGET_SITES 부산 기관 게시판의 IT·AI·보안 교육/세미나 공고

외부 라이브러리 없이 파이썬 3 표준 라이브러리만 사용합니다.
로컬 테스트:  python fetch_data.py  ->  site 폴더에서  python -m http.server 8080
"""
import email.utils
import html
import http.cookiejar
import json
import os
import re
import ssl
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
]
CISCO_PSIRT = "https://sec.cloudapps.cisco.com/security/center/psirtrss20/CiscoSecurityAdvisory.xml"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EVENTS_FILE = Path("events.json")

# 날씨 도시 (‹ › 버튼으로 넘김). 이름, 위도, 경도
CITIES = [
    ("부산", 35.1796, 129.0756),
    ("서울", 37.5665, 126.9780),
]

# KISA 보안취약점 정보포털 보안공지 (https://knvd.krcert.or.kr/info/vuln/notice)
KISA_DOMAIN = "https://knvd.krcert.or.kr"
KISA_PAGE = "https://knvd.krcert.or.kr/info/vuln/notice"
KISA_RSS = [
    "https://knvd.krcert.or.kr/rss/security/notice",
    "https://knvd.krcert.or.kr/rss/securityNotice.do",
]
KISA_MAX = 12      # 수집 개수

# NVD 신규 취약점: 점수 기준과 표시 개수
NVD_MIN = 8.0      # 이 점수 이상만 표시
WATCH_MIN = 7.0    # 아래 '주요 SW'는 이 점수 이상이면 표시 (Java, nginx 등)
NVD_MAX = 20       # 최신순으로 최대 몇 건
NVD_DAYS = 4       # 최근 며칠 안에 공개된 것을 대상으로 할지
WATCH_MAX = 8      # 주요 SW 항목을 목록에 우선 포함하는 최대 개수

# 주요 SW 감시 (표시 이름, 영문 설명에서 찾을 정규식). 필요하면 줄을 추가하세요.
WATCH = [
    ("Java", r"openjdk|\bjdk\b|\bjava(?!script)\b|graalvm"),
    ("nginx", r"\bnginx\b"),
    ("Apache", r"apache (?:http|httpd|tomcat|struts|log4j)|\btomcat\b|\bhttpd\b|\blog4j\b"),
    ("OpenSSH", r"\bopenssh\b"),
    ("OpenSSL", r"\bopenssl\b"),
    ("Spring", r"spring (?:framework|boot|cloud)"),
    ("PHP", r"\bphp\b"),
    ("Node.js", r"node\.js"),
]

# 위협 수준 (자체 산정 기준이며 국가 공식 경보 단계와 무관합니다)
#   점수 = 신규 악용(최근 2일, 최대 8) + 취급 제품 해당(7일, 건당 3점, 최대 6) + CVSS 8.0 이상 15건 이상(2점) + Cisco 치명·높음 권고(3점)
THREAT_MID = 5     # 이 점수 이상이면 "주의"
THREAT_HIGH = 10   # 이 점수 이상이면 "경계"

# 자동 넘김 간격(초). 0 이면 끔 (기본: 버튼·드래그로 수동 넘김)
AUTO = {"news": 0, "kev": 0, "nvd": 0, "psirt": 0, "kisa": 0, "events": 0, "wx": 0}

# 국내(부산) 교육·세미나·행사를 가져올 기관 게시판
TARGET_SITES = [    {        "name": "부산정보산업진흥원_ICT교육",        "url": "https://bipa.kr/board/training/list",        "domain": "https://bipa.kr",        "require_param": "seq="    },    {        "name": "부산정보산업진흥원_일반공고",        "url": "https://bipa.kr/board/notice/list",        "domain": "https://bipa.kr",        "require_param": "seq="    },    {        "name": "부산경제진흥원_소상공인디지털",        "url": "https://www.bepa.kr/kor/view.do?no=1502",        "domain": "https://www.bepa.kr",        "require_param": "idx="    },    {        "name": "부산경제진흥원_기업지원사업",        "url": "https://www.bepa.kr/kor/view.do?no=1505",        "domain": "https://www.bepa.kr",        "require_param": "idx="    },    {        "name": "부산과학기술고등교육진흥원_사업",        "url": "https://www.bistep.re.kr/board.es?mid=a10301010000&bid=0002",        "domain": "https://www.bistep.re.kr",        "require_param": "nttSn="    },    {        "name": "부산상공회의소_교육행사",        "url": "https://www.bcci.or.kr/",        "domain": "https://www.bcci.or.kr",        "require_param": "seq="    },    {        "name": "부산지방중소벤처기업청_공고",        "url": "https://www.mss.go.kr/site/busan/ex/bbs/List.do?cbIdx=277",        "domain": "https://www.mss.go.kr",        "require_param": "seq="    }]
BEXCO_URL = "https://www.bexco.co.kr/kor/CMS/EventScheduleMgr/list.do?mCode=MN214"
BEXCO_DOMAIN = "https://www.bexco.co.kr"

# 기술 키워드: 제목에 하나라도 있어야 통과
# 영문 약어(AI, SW 등)는 앞뒤에 영문자가 붙지 않은 경우만 일치로 봅니다.
TECH_KW = [
    "AI", "인공지능", "소프트웨어", "SW", "클라우드", "보안", "정보보호", "security",
    "디지털", "ICT", "데이터", "테크", "코딩", "tech", "아키텍처", "네트워크", "인프라", "dx", "ax", "llm"
]
# 보안 관련 공고는 목록 앞쪽에 먼저 보여주고 "보안" 태그를 붙입니다 (소문자로 비교)
SEC_KW = ["보안", "정보보호", "사이버", "해킹", "개인정보", "랜섬", "침해", "암호", "isms", "제로트러스트",
          "ciso", "시큐리티", "security", "cyber", "정보통신망", "취약점", "관제", "악성코드", "정보보안", "isms"]
# 제목 또는 링크에 있으면 제외
EXCLUDE_KW = [
    "마감", "종료", "완료", "결과", "state=end",
    "임차", "임대", "점포", "상가", "입주", "창업",
    "무역사절단", "사절단", "수출", "환급", "온누리", "전통시장", "자금지원", "안전경영", "해양산업",
    "웨딩", "결혼", "음식", "요리", "식품", "채용", "일자리", "취업", "면접", "결혼",
    "캠핑", "펫", "반려동물", "뷰티", "패션", "미술", "공연", "축제", "관광", "여행", "국악",
    "입찰", "계약", "낙찰", "용역", "합격", "성료", "마쳐", "마치", "성황", "폐막", "수료"
]
# 행사 종류 자동 분류 (앞에서부터 먼저 일치하는 것을 사용)
EVENT_TYPES = [
    ("웨비나", ["웨비나", "온라인", "강의", "강연"]),
    ("컨퍼런스", ["컨퍼런스", "콘퍼런스"]),
    ("박람회", ["박람회", "전시회", "페어", "expo"]),
    ("교육", ["교육", "강좌", "강의", "실습", "훈련", "과정", "양성", "특강", "캠프"]),
    ("세미나", ["세미나", "포럼", "설명회", "워크숍", "강연"]),
]

OUT = Path("site")
UA = {"User-Agent": "Mozilla/5.0 (BeeBoard/1.0)"}
KST = dt.timezone(dt.timedelta(hours=9))

# 기관 사이트용 브라우저 헤더
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.9,en;q=0.9",
}

# SSL 인증서 검증 해제 + 오래된 서버 접속 허용
_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE
try:
    _CTX.set_ciphers("DEFAULT@SECLEVEL=1")
except Exception:
    pass
try:
    _CTX.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
except Exception:
    pass

_KEV_CACHE = None   # KEV 원본 (한 번만 내려받아 재사용)
_NVD_TOTAL = None   # 최근 2일 CVSS 8.0 이상 CVE 건수
EV_LOG = []         # 행사 수집 결과 요약 (화면에 표시)


# ----------------------------- 유틸 -----------------------------
def http_get(url, timeout=25):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def decode_html(raw, ctype=""):
    """서버가 알려준 인코딩 → meta 태그 → utf-8 → euc-kr → cp949 순서로 시도"""
    cands = []
    m = re.search(r"charset=([\w\-]+)", ctype or "", re.I)
    if m:
        cands.append(m.group(1))
    m = re.search(rb"charset=[\"']?([\w\-]+)", raw[:3000], re.I)
    if m:
        cands.append(m.group(1).decode("ascii", "ignore"))
    cands += ["utf-8", "euc-kr", "cp949"]
    for enc in cands:
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "ignore")


def fetch_html(url, domain, timeout=15):
    """먼저 사이트 대문을 방문해 쿠키를 받고, Referer 를 붙여 목록을 요청"""
    h = dict(BROWSER_HEADERS)
    h["Referer"] = domain + "/"
    last = None
    for _ in range(2):
        try:
            jar = http.cookiejar.CookieJar()
            op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar),
                                             urllib.request.HTTPSHandler(context=_CTX))
            try:
                op.open(urllib.request.Request(domain, headers=h), timeout=8).read(2048)
            except Exception:
                pass
            with op.open(urllib.request.Request(url, headers=h), timeout=timeout) as r:
                raw = r.read()
                ctype = r.headers.get("Content-Type", "")
            return decode_html(raw, ctype)
        except Exception as e:
            last = e
            time.sleep(1.5)
    raise last


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
    s = re.sub(r"<[^>]+>", "", s)
    return re.sub(r"\s+", " ", s).strip()


def rss_items(root, source):
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


def parse_rss(url, source):
    return rss_items(ET.fromstring(http_get(url)), source)


def parse_rss_text(text, source):
    text = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.lstrip("\ufeff"))
    return rss_items(ET.fromstring(text), source)


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
    (("vpn", "firewall", "adaptive security appliance", "asa", "ftd", "firepower", "fortios", "fortigate",
      "pan-os", "sonicwall", "globalprotect", "netscaler", "big-ip", "secure client"), "방화벽·VPN"),
    (("exchange", "mail", "webmail", "zimbra", "roundcube", "postfix", "esa"), "메일 서버"),
    (("chrome", "chromium", "firefox", "edge", "safari", "browser", "webkit"), "웹 브라우저"),
    (("windows", "kernel", "linux", "ubuntu", "android", "ios", "macos", "apple"), "OS·커널"),
    (("wordpress", "php", "apache", "nginx", "tomcat", "iis", "node.js", "openssh", "ssh", "web", "joomla",
      "drupal", "struts", "spring", "java", "openjdk"), "웹·서버 SW"),
    (("sql", "oracle", "mysql", "postgres", "postgresql", "database", "mongodb", "redis"), "데이터베이스"),
    (("router", "switch", "meraki", "access point", "wlc", "camera", "nas", "synology", "qnap", "d-link",
      "dlink", "tp-link", "zyxel"), "네트워크·IoT 장비"),
    (("vmware", "esxi", "vcenter", "hyper-v", "citrix", "kubernetes", "docker", "gitlab", "jenkins", "ibm",
      "sap", "gpustack", "aspera"), "서버·플랫폼"),
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


def watch_label(text):
    """주요 SW(Java, nginx 등) 해당 시 표시 이름, 아니면 빈 문자열"""
    low = (text or "").lower()
    for name, pat in WATCH:
        if re.search(pat, low):
            return name
    return ""


def guess_product(desc):
    """NVD 영문 설명에서 제품명 부분만 대략 추출"""
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
    title = re.sub(r"\s+Vulnerabilit(?:y|ies)$", "", x["title"])
    return {"title": title, "link": x.get("link", ""), "ts": x["ts"],
            "atk": atk, "eff": eff, "lvl": lvl, "cat": cat, "sev": sev}


# ----------------------------- 수집: 뉴스 / 취약점 -----------------------------
# 보안과 무관한 기사(경조사·인사·동정 등) 제외
#   - [화촉] [부고] [인사] 처럼 말머리가 붙은 기사
#   - 결혼식·청첩·부친상 처럼 경조사가 분명한 표현
#   (제목에 '결혼'이 들어간 일반 보안 기사는 통과: 예) 결혼정보회사 개인정보 유출)
NOISE_TAG_RE = re.compile(r"^\s*[\[\(【<]\s*(?:화촉|결혼|혼사|청첩|부고|부음|경조사?|인사|동정)\s*[\]\)】>]")
NOISE_RE = re.compile(
    r"화촉|청첩|혼례|결혼식|결혼\s*(?:합니다|했습니다|소식)|(?:장남|장녀|차남|차녀|아들|딸|본인)\s*결혼"
    r"|부고|부음|부친상|모친상|빙부상|빙모상|장인상|장모상|시부상|시모상|조부상|조모상|별세|빈소|발인|영결식")


def is_noise(title):
    t = title or ""
    return bool(NOISE_TAG_RE.search(t) or NOISE_RE.search(t))


def fetch_news():
    items, ok = [], 0
    for name, url in NEWS_FEEDS:
        try:
            items += [x for x in parse_rss(url, name) if not is_noise(x["title"])]
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


def nvd_ts(s):
    """NVD 공개 시각(UTC)을 epoch 초로 변환"""
    try:
        return int(dt.datetime.fromisoformat(str(s)[:19]).replace(tzinfo=dt.timezone.utc).timestamp())
    except Exception:
        return 0


def best_score(metrics):
    """CVSS v4.0 / v3.1 / v3.0 점수 중 가장 높은 값 (제조사·NVD 평가 모두 포함)"""
    best = 0
    for k in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        for m in (metrics or {}).get(k, []) or []:
            try:
                sc = float(m.get("cvssData", {}).get("baseScore", 0))
            except Exception:
                sc = 0
            if sc > best:
                best = sc
    return best


def fetch_nvd():
    """NVD 에서 최근 NVD_DAYS 일 공개분을 받아 CVSS(v4.0 포함) NVD_MIN 이상, 주요 SW 는 WATCH_MIN 이상을 최신 공개순으로 NVD_MAX 건 반환"""
    global _NVD_TOTAL
    now = dt.datetime.now(dt.timezone.utc)
    start = now - dt.timedelta(days=NVD_DAYS)
    q = urllib.parse.urlencode({
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 2000,
    })
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q

    def get_page(start):
        url = base + ("&startIndex=%d" % start if start else "")
        last = None
        for _ in range(2):
            try:
                return json.loads(http_get(url, 120).decode("utf-8"))
            except Exception as e:
                last = e
                print("[재시도] NVD", e)
                time.sleep(8)
        raise last

    # NVD 는 한 번에 최대 2000건만 주므로, 총 건수(totalResults)만큼 startIndex 로 이어서 모두 받음
    data = get_page(0)
    vulns = list(data.get("vulnerabilities", []))
    total = int(data.get("totalResults") or len(vulns))
    pages = 1
    while len(vulns) < total and pages < 8:
        time.sleep(7)        # 키 없는 NVD API 는 30초에 5회 제한
        try:
            more = get_page(len(vulns)).get("vulnerabilities", [])
        except Exception as e:
            print("[경고] NVD 다음 페이지 실패 (일부만 사용):", e)
            break
        if not more:
            break
        vulns += more
        pages += 1
    print("NVD: 전체", total, "건 중", len(vulns), "건 수신 (", pages, "페이지 )")
    data = {"vulnerabilities": vulns}
    found = {}
    for v in data.get("vulnerabilities", []):
        c = v.get("cve", {})
        if c.get("vulnStatus") == "Rejected":
            continue
        score = best_score(c.get("metrics", {}))
        desc = clean(next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), ""))
        wl = watch_label(desc)
        if score < (WATCH_MIN if wl else NVD_MIN):
            continue
        atk, eff, lvl = classify(desc)
        cid = c.get("id", "")
        found[cid] = {"cve": cid, "score": score, "desc": desc[:110], "ts": nvd_ts(c.get("published", "")),
                      "atk": atk, "eff": eff, "lvl": lvl, "cat": categorize(desc),
                      "prod": guess_product(desc), "watch": wl}
    items = sorted(found.values(), key=lambda x: (x["ts"], x["score"]), reverse=True)
    cut = time.time() - 48 * 3600
    _NVD_TOTAL = sum(1 for x in items if x["ts"] >= cut and x["score"] >= NVD_MIN)
    # 주요 SW(Java, nginx 등)를 먼저 확보한 뒤 나머지를 최신순으로 채우고, 전체를 최신순으로 정렬
    watch = [x for x in items if x["watch"]][:WATCH_MAX]
    wids = set(x["cve"] for x in watch)
    rest = [x for x in items if x["cve"] not in wids][:max(0, NVD_MAX - len(watch))]
    out = sorted(watch + rest, key=lambda x: (x["ts"], x["score"]), reverse=True)[:NVD_MAX]
    print("NVD: 조회", len(data.get("vulnerabilities", [])), "건 / 기준 통과", len(items),
          "건 / 주요 SW", len(watch), "건")
    return out


def fetch_psirt():
    items = parse_rss(CISCO_PSIRT, "Cisco")
    items.sort(key=lambda x: x["ts"], reverse=True)
    return [psirt_item(x) for x in items[:6]]


# ----------------------------- 수집: KISA 보안공지 -----------------------------
A_RE = re.compile(r"<a\b([^>]*)>(.*?)</a>", re.S | re.I)
HREF_RE = re.compile(r"href\s*=\s*[\"']([^\"']+)[\"']", re.I)
DATE_RE = re.compile(r"(20\d\d)[.\-/]\s?(\d{1,2})[.\-/]\s?(\d{1,2})")


def scrape_kisa():
    """RSS 가 안 될 때: 보안공지 목록 페이지에서 상세 링크를 직접 찾음"""
    page = fetch_html(KISA_PAGE, KISA_DOMAIN, 20)
    out, seen = [], set()
    for m in A_RE.finditer(page):
        hm = HREF_RE.search(m.group(1))
        if not hm:
            continue
        href = html.unescape(hm.group(1)).strip()
        if "notice/detail" not in href:
            continue
        title = clean(m.group(2))
        if len(title) < 4 or href in seen:
            continue
        seen.add(href)
        date = ""
        dm = DATE_RE.search(page[m.end(): m.end() + 400])
        if dm:
            date = "%s-%02d-%02d" % (dm.group(1), int(dm.group(2)), int(dm.group(3)))
        out.append({"title": title, "link": urllib.parse.urljoin(KISA_PAGE, href), "ts": 0, "date": date})
    return out


def fetch_kisa():
    items, how = [], ""
    for url in KISA_RSS:
        try:
            got = parse_rss_text(fetch_html(url, KISA_DOMAIN, 20), "KISA")
            if got:
                items, how = got, "RSS"
                break
            print("[참고] KISA RSS 항목 없음:", url)
        except Exception as e:
            print("[실패] KISA RSS", url, e)
    if not items:
        try:
            items, how = scrape_kisa(), "HTML"
        except Exception as e:
            print("[실패] KISA 페이지", e)
    if not items:
        raise RuntimeError("KISA 보안공지 수집 실패")
    out = []
    for it in items:
        ts = it.get("ts", 0)
        date = it.get("date", "")
        if ts:
            date = dt.datetime.fromtimestamp(ts, KST).strftime("%Y-%m-%d")
        out.append({"title": it["title"], "link": urllib.parse.urljoin(KISA_PAGE, it.get("link", "")),
                    "ts": ts, "date": date})
    if all(x["ts"] for x in out):
        out.sort(key=lambda x: x["ts"], reverse=True)
    print("[수집] KISA 보안공지", len(out), "건 (" + how + ")")
    return out[:KISA_MAX]


# ----------------------------- 수집: 국내(부산) 보안·IT 행사 -----------------------------
def event_type(title, given=""):
    if given:
        return given
    for label, keys in EVENT_TYPES:
        if any(k in title for k in keys):
            return label
    return "행사"


def tech_match(title):
    """기술 키워드 일치 여부. 영문 약어는 앞뒤에 영문자가 붙지 않아야 일치"""
    for kw in TECH_KW:
        if kw.isascii():
            if re.search(r"(?<![A-Za-z])" + re.escape(kw) + r"(?![A-Za-z])", title):
                return True
        elif kw in title:
            return True
    return False


def is_sec(title):
    low = title.lower()
    return any(k in low for k in SEC_KW)


def is_target_title(title, href=""):
    """짧은 제목 제외, 제외 키워드(제목+링크), 지난 연도 제목, 기술 키워드 필수"""
    if len(title) < 5:
        return False
    if any(k in (href + " " + title) for k in EXCLUDE_KW):
        return False
    year = dt.datetime.now(KST).year
    if any(str(y) in title for y in range(2020, year)):
        return False
    return tech_match(title)


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
        out.append({"kind": "event", "type": event_type(title, e.get("type", "")),
                    "date": s.isoformat(), "end": en.isoformat(), "time": e.get("time", ""),
                    "title": title, "place": e.get("place", ""), "link": e.get("link", "")})
    out.sort(key=lambda x: (x["date"], x["title"]))
    return out[:10]


def scrape_site(site):
    """기관 게시판 목록에서 게시글 링크(require_param 포함)를 찾아 IT·AI·보안 교육/공고만 추림"""
    page = fetch_html(site["url"], site["domain"], 15)
    out, seen = [], set()
    for m in A_RE.finditer(page):
        hm = HREF_RE.search(m.group(1))
        if not hm:
            continue
        href = html.unescape(hm.group(1)).strip()
        if not href or href.lower().startswith(("javascript", "#", "mailto")):
            continue
        if site["require_param"] not in href:
            continue
        title = clean(m.group(2))
        if not is_target_title(title, href):
            continue
        key = re.sub(r"\W", "", title)[:30]
        if key in seen:
            continue
        seen.add(key)
        posted = ""
        dm = DATE_RE.search(page[m.end(): m.end() + 500])
        if dm:
            posted = "%s-%02d-%02d" % (dm.group(1), int(dm.group(2)), int(dm.group(3)))
        out.append({"kind": "board", "site": site["name"].split("_")[0], "type": event_type(title),
                    "sec": is_sec(title), "title": title,
                    "link": urllib.parse.urljoin(site["url"], href), "posted": posted})
    return out[:6]


def fetch_bexco():
    """벡스코 행사일정에서 IT·AI·보안 관련 행사 추출 (페이지 구조를 날짜 범위 기준으로 해석)"""
    page = fetch_html(BEXCO_URL, BEXCO_DOMAIN, 20)
    page = re.sub(r"(?is)<(script|style).*?</\1>", " ", page)
    toks = [clean(t) for t in re.split(r"<[^>]+>", page)]
    toks = [t for t in toks if t]
    rng = re.compile(r"(20\d\d-\d\d-\d\d)\s*~\s*(20\d\d-\d\d-\d\d)")
    noise = re.compile(r"^(상세보기|진행중|이벤트|회의|전시|공연|D-\d+|D-Day|예정|종료|포스터형|리스트형)$")
    today = dt.datetime.now(KST).date().isoformat()
    out, seen = [], set()
    for i, t in enumerate(toks):
        m = rng.search(t)
        if not m:
            continue
        title = ""
        for j in range(i - 1, max(i - 6, -1), -1):
            c = toks[j]
            if noise.match(c) or len(c) < 4 or rng.search(c):
                continue
            title = c
            break
        if not title or m.group(2) < today:
            continue
        if not is_target_title(title):
            continue
        place = t[m.end():].strip()
        if not place and i + 1 < len(toks) and not rng.search(toks[i + 1]):
            place = toks[i + 1]
        key = title + m.group(1)
        if key in seen:
            continue
        seen.add(key)
        out.append({"kind": "bexco", "type": event_type(title), "sec": is_sec(title),
                    "date": m.group(1), "end": m.group(2), "time": "", "title": title,
                    "place": ("벡스코 " + place[:30]) if place else "벡스코", "link": BEXCO_URL})
    out.sort(key=lambda x: (not x["sec"], x["date"]))
    return out[:6]


def fetch_events():
    EV_LOG[:] = []
    reg = load_registered_events()

    bex = []
    try:
        bex = fetch_bexco()
        print("[수집] 벡스코", len(bex), "건")
    except Exception as e:
        print("[실패] 벡스코", e)

    boards, ok_sites = [], 0
    for s in TARGET_SITES:
        try:
            got = scrape_site(s)
            ok_sites += 1
            print("[수집]", s["name"], len(got), "건")
            boards += got
        except Exception as e:
            print("[실패]", s["name"], e)
        time.sleep(1.2)

    cutoff = (dt.datetime.now(KST).date() - dt.timedelta(days=60)).isoformat()
    boards.sort(key=lambda x: x["posted"], reverse=True)      # 게시일 최신순 (게시일 없는 항목은 뒤)
    boards.sort(key=lambda x: not x["sec"])                    # 보안 관련 공고를 앞으로 (순서 유지)
    seen, uniq = set(), []
    for b in boards:
        key = re.sub(r"\W", "", b["title"])[:30]
        if key in seen or (b["posted"] and b["posted"] < cutoff):
            continue
        seen.add(key)
        uniq.append(b)
    boards = uniq[:10]

    EV_LOG.extend(["직접등록 %d건" % len(reg), "벡스코 %d건" % len(bex),
                   "기관 게시판 %d건 (%d곳 중 %d곳 응답)" % (len(boards), len(TARGET_SITES), ok_sites)])
    if ok_sites == 0:
        EV_LOG.append("기관 사이트 접속 실패(해외 서버 차단 가능)")
    print("행사:", " / ".join(EV_LOG))
    return reg + bex + boards


# ----------------------------- 수집: 날씨 (부산·서울) -----------------------------
def fetch_city_weather(name, lat, lon):
    q = urllib.parse.urlencode({
        "latitude": lat, "longitude": lon,
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
    return {"name": name, "temp": round(d["current"]["temperature_2m"]), "code": d["current"]["weather_code"],
            "days": days}


def fetch_weather():
    cities = []
    for name, lat, lon in CITIES:
        try:
            cities.append(fetch_city_weather(name, lat, lon))
        except Exception as e:
            print("[실패] 날씨", name, e)
    if not cities:
        raise RuntimeError("날씨 수집 실패")
    return {"cities": cities}


# ----------------------------- 통계 (위협 수준) -----------------------------
def build_stats(psirt, prev_nvd=0):
    kev = _KEV_CACHE
    if not kev:
        raise RuntimeError("KEV 데이터 없음")
    # CISA 등재일은 미국 기준이라 UTC 날짜를 기준으로 계산
    anchor = dt.datetime.now(dt.timezone.utc).date()
    s7 = (anchor - dt.timedelta(days=6)).isoformat()
    s1 = (anchor - dt.timedelta(days=1)).isoformat()

    new2, ours7_ids = 0, []
    vulns = sorted(kev.get("vulnerabilities", []), key=lambda v: v.get("dateAdded", ""), reverse=True)
    for v in vulns:
        a = v.get("dateAdded", "")
        if a < s7:
            break
        if a >= s1:
            new2 += 1
        if any(k in v.get("vendorProject", "").lower() for k in OUR_VENDORS):
            ours7_ids.append(v.get("cveID", ""))

    now = time.time()
    psirt_hi = any(p.get("sev") in ("치명", "높음") and now - p.get("ts", 0) <= 86400 for p in (psirt or []))
    nvd = _NVD_TOTAL if _NVD_TOTAL is not None else prev_nvd
    score = min(new2, 8) + 3 * min(len(ours7_ids), 2) + (2 if nvd >= 15 else 0) + (3 if psirt_hi else 0)
    level = "경계" if score >= THREAT_HIGH else ("주의" if score >= THREAT_MID else "안정")
    return {"new2": new2, "ours7": len(ours7_ids), "ours7_ids": ours7_ids[:3],
            "nvd": nvd, "score": score, "level": level}


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
            ("psirt", fetch_psirt, []), ("kisa", fetch_kisa, []), ("events", fetch_events, []),
            ("weather", fetch_weather, {}))
    for key, fn, empty in jobs:
        try:
            data[key] = fn()
            print("[성공]", key)
        except Exception as e:
            print("[실패]", key, e)
            data["errors"].append(key)
            data[key] = prev.get(key, empty)
    data["ev_log"] = list(EV_LOG) if "events" not in data["errors"] else prev.get("ev_log", [])
    try:
        data["stats"] = build_stats(data.get("psirt", []), (prev.get("stats") or {}).get("nvd", 0))
        print("[성공] stats 위협수준:", data["stats"]["level"], "점수:", data["stats"]["score"])
    except Exception as e:
        print("[실패] stats", e)
        data["errors"].append("stats")
        data["stats"] = prev.get("stats", {})
    OUT.mkdir(exist_ok=True)
    (OUT / "data.json").write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    (OUT / "index.html").write_text(INDEX_HTML.replace("__AUTO__", json.dumps(AUTO)), encoding="utf-8")
    (OUT / ".nojekyll").write_text("", encoding="utf-8")
    print("완료:", len(data["news"]), "news,", len(data["kev"]), "kev,", len(data["nvd"]), "nvd,",
          len(data["kisa"]), "kisa,", len(data["events"]), "events")


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
 padding:14px;display:grid;grid-template-rows:116px 66px 160px 310px 290px 260px 250px 1fr 52px 28px;row-gap:10px}
.panel{background:rgba(15,28,52,.85);border:1px solid rgba(34,211,238,.18);border-radius:20px;padding:16px 22px;overflow:hidden;position:relative}
.hd{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.ttl{font-size:26px;font-weight:900;letter-spacing:-.5px;color:#22D3EE;padding-left:12px;border-left:6px solid #22D3EE;line-height:1.1;min-width:0;white-space:nowrap}
.ttl small{font-size:18px;font-weight:500;color:#7C93B2;margin-left:10px}
.pg{display:flex;align-items:center;flex:none;margin-left:10px}
.pb{width:44px;height:38px;border:0;border-radius:10px;background:rgba(34,211,238,.15);color:#22D3EE;font-size:28px;font-weight:900;line-height:36px;cursor:pointer;margin-left:6px}
.pb:hover,.pb:focus{outline:2px solid #22D3EE;outline-offset:1px}
.pb.sm{width:34px;height:30px;font-size:22px;line-height:28px;margin-left:4px}
.pd{display:inline-block;margin:0 6px;min-width:44px;text-align:center;font-size:20px;font-weight:700;color:#7C93B2}
.fade{transition:opacity .25s ease;min-height:0}
.fade.out{opacity:0}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
/* 헤더 */
#head{display:grid;grid-template-columns:1fr auto;align-items:center;padding:0 10px}
.brand{display:flex;align-items:center}
.brand svg{margin-right:16px}
.brand b{font-size:40px;font-weight:900;letter-spacing:-1px;display:block;line-height:1.1}
.brand span{font-size:20px;color:#7C93B2}
.clock{text-align:right}
#clock{font-size:60px;font-weight:900;color:#22D3EE;line-height:60px;letter-spacing:-2px}
#date{font-size:22px;font-weight:700;line-height:28px}
/* 상태 바 */
#status{display:flex;align-items:center;padding:6px 18px}
.chip{display:flex;align-items:baseline;font-size:20px;font-weight:700;padding:4px 16px;border-radius:12px;background:rgba(255,255,255,.08);margin-right:22px;white-space:nowrap}
.chip b{font-size:30px;font-weight:900;margin-left:8px}
.chip small{font-size:13px;margin-left:8px;opacity:.7;font-weight:500}
.chip.lv0{background:#34D399;color:#04281c}
.chip.lv1{background:#FACC15;color:#111}
.chip.lv2{background:#F97316;color:#111}
#stats{display:flex;flex:1;justify-content:space-between}
.st{display:flex;align-items:baseline;white-space:nowrap}
.st .lb{font-size:17px;color:#9FB4CE;margin-right:8px}
.st b{font-size:38px;font-weight:900;color:#22D3EE;line-height:1}
.st em{font-style:normal;font-size:17px;color:#9FB4CE;margin-left:3px}
.st .cid{font-family:Consolas,monospace;font-size:15px;color:#F97316;margin-left:8px}
/* 날씨 */
#wx{display:grid;grid-template-columns:280px 1fr;column-gap:18px;padding:12px 18px}
.now{border-right:1px solid rgba(34,211,238,.18);padding-right:14px}
.wh{display:flex;align-items:center;justify-content:space-between;margin-bottom:2px}
.now .ttl{font-size:24px}
.wpg{display:flex;align-items:center;flex:none}
.wpg .pd{min-width:42px;margin:0 2px;font-size:16px}
.now .big{font-size:56px;font-weight:900;line-height:1}
.now .cond{font-size:20px;font-weight:700;color:#A9C1DE;line-height:26px}
.week{display:grid;grid-template-columns:repeat(7,1fr);column-gap:8px}
.day{text-align:center;border-radius:14px;padding:4px 2px;background:rgba(255,255,255,.04)}
.day.today{border:2px solid #22D3EE;background:rgba(34,211,238,.1)}
.day.rain{background:rgba(59,130,246,.22)}
.day .dn{font-size:20px;font-weight:700;line-height:24px}
.day .dd{font-size:14px;color:#7C93B2;line-height:16px}
.day .tt{font-size:20px;font-weight:700;line-height:24px}
.day .tt i{font-style:normal;color:#7C93B2;font-weight:500}
.day .pp{font-size:15px;color:#60A5FA;line-height:18px}
/* 뉴스 행 */
.row{display:grid;grid-template-columns:100px 1fr 80px;column-gap:12px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.row:last-child{border-bottom:0}
.src{font-size:17px;font-weight:700;text-align:center;border-radius:8px;padding:4px 0;background:rgba(34,211,238,.15);color:#22D3EE}
.t{font-size:25px;font-weight:700;line-height:1.28;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ago{font-size:17px;color:#7C93B2;text-align:right}
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
/* 신규 고위험 CVE (NVD) */
a.nv,div.nv{display:block;padding:4px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.nv:last-child{border-bottom:0}
.nv1{display:flex;align-items:center;height:28px}
.nv1 b{display:inline-block;min-width:54px;text-align:center;border-radius:6px;margin-right:8px;padding:0 6px;font-size:19px;line-height:26px}
.nvc{font-family:Consolas,monospace;color:#22D3EE;font-weight:700;font-size:19px;margin-right:8px}
.nvd2{margin-left:auto;font-size:15px;color:#7C93B2;white-space:nowrap}
.nv2{font-size:17px;line-height:22px;color:#C7D6EA;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sc9{background:#EF4444;color:#fff}.sc7{background:#F97316;color:#111}
.tgW{background:#A78BFA;color:#111}
/* 두 칸 (Cisco 권고 + KISA 보안공지) */
.two{display:grid;grid-template-columns:1fr 1fr;column-gap:14px}
.two .panel{padding:14px 18px}
.mini{padding:3px 0;border-bottom:1px solid rgba(255,255,255,.07);font-size:20px;line-height:26px}
.mini:last-child{border-bottom:0}
.kt{font-size:19px;font-weight:700;line-height:24px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.ks{font-size:15px;line-height:20px;color:#7C93B2}
.empty{color:#7C93B2;font-size:20px;padding:10px 0;line-height:1.5}
/* 국내 보안행사 */
.ev{display:grid;grid-template-columns:1fr 100px;column-gap:14px;align-items:center;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.07)}
.ev:last-child{border-bottom:0}
.evl{display:flex;align-items:center;margin-bottom:2px}
.dt{font-size:20px;font-weight:900;color:#22D3EE;white-space:nowrap;margin-right:10px}
.tt2{font-size:23px;font-weight:700;line-height:30px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.pl{font-size:17px;line-height:22px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
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
.tgK{background:#A78BFA;color:#111}
/* 링크 */
a.lk{color:inherit;text-decoration:none;cursor:pointer}
a.mini{display:block}
a.lk:hover,a.lk:focus{outline:2px solid #22D3EE;outline-offset:2px;border-radius:8px;background:rgba(34,211,238,.08)}
#foot{display:flex;justify-content:space-between;align-items:center;font-size:18px;color:#7C93B2;padding:0 10px}
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
      <div style="margin-left:22px"><b style="font-size:34px">오늘의 보안 브리핑</b><span>Daily Security Briefing</span></div>
    </div>
    <div class="clock"><div id="clock">--:--</div><div id="date"></div></div>
  </div>

  <div id="status" class="panel">
    <div id="chip" class="chip lv0">위협 수준<b>-</b><small>자체 산정</small></div>
    <div id="stats">
      <div class="st"><span class="lb">신규 악용(2일)</span><b id="c1">0</b><em>건</em></div>
      <div class="st"><span class="lb">CVSS 8.0+(2일)</span><b id="c2">0</b><em>건</em></div>
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
    <div class="hd"><div class="ttl">신규 고위험 CVE<small>NVD · CVSS 8.0 이상 + 주요 SW(Java·nginx 등) · 최신순 20건</small></div>
      <div class="pg"><button class="pb" onclick="nav('nvd',-1)">&lsaquo;</button><span class="pd" id="d-nvd"></span><button class="pb" onclick="nav('nvd',1)">&rsaquo;</button></div></div>
    <div id="nvd" class="fade"></div>
  </div>

  <div class="two">
    <div class="panel">
      <div class="hd"><div class="ttl">Cisco 보안 권고<small>PSIRT</small></div>
        <div class="pg"><button class="pb" onclick="nav('psirt',-1)">&lsaquo;</button><span class="pd" id="d-psirt"></span><button class="pb" onclick="nav('psirt',1)">&rsaquo;</button></div></div>
      <div id="psirt" class="fade"></div>
    </div>
    <div class="panel">
      <div class="hd"><div class="ttl">KISA 보안공지<small>KNVD</small></div>
        <div class="pg"><button class="pb" onclick="nav('kisa',-1)">&lsaquo;</button><span class="pd" id="d-kisa"></span><button class="pb" onclick="nav('kisa',1)">&rsaquo;</button></div></div>
      <div id="kisa" class="fade"></div>
    </div>
  </div>

  <div class="panel">
    <div class="hd"><div class="ttl">국내 보안 행사<small>IT·AI·보안 교육/세미나 · 벡스코·부산 기관 공고</small></div>
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
function safe(fn){try{fn()}catch(e){if(window.console)console.log('render error',e)}}

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

/* ---------- 날씨 (부산 / 서울 버튼 넘김) ---------- */
var WXI=0;
function wxList(w){
 if(!w)return [];
 if(w.cities)return w.cities;
 if(w.days)return [{name:'부산',temp:w.temp,code:w.code,days:w.days}];
 return []}
function renderWx(w){
 var L=wxList(w);
 if(!L.length){$('wx').innerHTML='<div class="empty">날씨 데이터 없음</div>';return}
 if(WXI>=L.length)WXI=0;
 var c=L[WXI],ts=todayStr();
 var pager=L.length>1?'<div class="wpg"><button class="pb sm" onclick="wxnav(-1)">&lsaquo;</button><span class="pd">'+(WXI+1)+' / '+L.length+'</span><button class="pb sm" onclick="wxnav(1)">&rsaquo;</button></div>':'';
 var h='<div class="now"><div class="wh"><div class="ttl">'+esc(c.name)+' 날씨</div>'+pager+'</div><div style="display:flex;align-items:center">'+ico(c.code,52)+'<div class="big" style="margin-left:6px">'+c.temp+'°</div></div><div class="cond">'+label(c.code)+' · 최고 '+c.days[0].max+'° / 최저 '+c.days[0].min+'°</div></div><div class="week">';
 for(var i=0;i<c.days.length;i++){var d=c.days[i],dt=new Date(d.date+'T00:00:00'),rain=kind(d.code)=='rain'||kind(d.code)=='snow';
  h+='<div class="day'+(d.date==ts?' today':'')+(rain?' rain':'')+'"><div class="dn">'+(d.date==ts?'오늘':DAYS[dt.getDay()])+'</div><div class="dd">'+pad(dt.getMonth()+1)+'/'+pad(dt.getDate())+'</div>'+ico(d.code,38)+'<div class="tt">'+d.max+'° <i>'+d.min+'°</i></div><div class="pp">강수 '+d.pop+'%</div></div>'}
 $('wx').innerHTML=h+'</div>'}
function wxnav(d){
 if(!DATA)return;
 var L=wxList(DATA.weather);if(L.length<2)return;
 WXI=(WXI+d+L.length)%L.length;
 renderWx(DATA.weather)}

/* ---------- 버튼·드래그 넘김 패널 (뉴스 · 긴급 취약점 · 신규 CVE · Cisco · KISA · 국내 행사) ---------- */
var LIST={news:[],kev:[],nvd:[],psirt:[],kisa:[],events:[]};
var PER={news:3,kev:3,nvd:3,psirt:3,kisa:2,events:2};
var MAXP={news:4,kev:3,nvd:7,psirt:2,kisa:6,events:8};
var PAGE={news:0,kev:0,nvd:0,psirt:0,kisa:0,events:0};
var EMPTY={
 news:'<div class="empty">뉴스 데이터 없음</div>',
 kev:'<div class="empty">KEV 데이터 없음</div>',
 nvd:'<div class="empty">최근 며칠간 기준을 넘는 신규 CVE 없음</div>',
 psirt:'<div class="empty">Cisco 권고 데이터 없음</div>',
 kisa:'<div class="empty">KISA 보안공지를 불러오지 못했습니다</div>',
 events:'<div class="empty">표시할 국내 보안 행사가 없습니다</div>'};
var SUPPRESS=0;
function evHtml(e){
 var ts=todayStr(),tn=dnum(ts),t=esc(e.type||'행사');
 if(e.kind=='board'){
  return A('ev',e.link,'<div class="evm"><div class="evl"><span class="tg tgS">'+esc(e.site)+'</span>'+(e.sec?'<span class="tg tgE">보안</span>':'')+'<span class="tg tgN">'+t+'</span></div><div class="tt2">'+esc(e.title)+'</div><div class="pl">'+(e.posted?esc(e.posted)+' 게시':'게시일 미확인')+' · 일정은 원문에서 확인</div></div><span class="bd nw">공고</span>')}
 var sd=dnum(e.date),ed=dnum(e.end),bd,bc='';
 if(tn>=sd&&tn<=ed){bd=(sd==ed)?'오늘':'진행중';bc=' hot'}
 else{var df=sd-tn;bd='D-'+df;if(df<=7)bc=' soon'}
 var dtx=md(e.date)+(e.end!=e.date?' ~ '+md(e.end):'')+(e.time?' '+esc(e.time):'');
 var tag=(e.kind=='bexco')?'<span class="tg tgE">벡스코</span><span class="tg tgN">'+t+'</span>':'<span class="tg tgN">'+t+'</span>';
 return A('ev',e.link,'<div class="evm"><div class="evl"><span class="dt">'+dtx+'</span>'+tag+'</div><div class="tt2">'+esc(e.title)+'</div>'+(e.place?'<div class="pl">'+esc(e.place)+'</div>':'')+'</div><span class="bd'+bc+'">'+bd+'</span>')}
var RENDER={
 news:function(n){return A('row',n.link,'<span class="src">'+esc(n.src)+'</span><div class="t">'+esc(n.title)+'</div><span class="ago">'+ago(n.ts)+'</span>')},
 kev:function(v){return A('kev',NVD+v.cve,'<div class="cve">'+esc(v.cve)+'</div><div><div class="a">'+(v.ours?'<span class="tag our">취급</span>':'')+(v.ransom?'<span class="tag rw">랜섬웨어</span>':'')+'<span class="atk l'+(v.lvl||3)+'">'+esc(v.atk)+'</span>'+esc(v.vendor)+' '+esc(v.product)+'</div><div class="b">'+esc(v.cat)+' · '+esc(v.eff)+' <span class="sol">→ '+esc(v.sol)+'</span></div></div><div class="due">조치 '+esc(String(v.due).slice(5))+'</div>')},
 nvd:function(n){var dd=new Date((n.ts||0)*1000);
  return A('nv',NVD+n.cve,'<div class="nv1"><b class="'+(n.score>=9?'sc9':'sc7')+'">'+n.score+'</b><span class="atk l'+(n.lvl||3)+'">'+esc(n.atk)+'</span><span class="nvc">'+esc(n.cve)+'</span>'+(n.watch?'<span class="tg tgW">'+esc(n.watch)+'</span>':'')+'<span class="nvd2">'+(n.ts?pad(dd.getMonth()+1)+'/'+pad(dd.getDate())+' '+pad(dd.getHours())+':'+pad(dd.getMinutes())+' 공개':'')+'</span></div><div class="nv2">'+esc(n.cat)+' · '+esc(n.eff)+(n.prod?' · '+esc(n.prod):'')+'</div>')},
 psirt:function(p){return A('mini',p.link,'<span class="atk l'+(p.lvl||3)+'">'+esc(p.atk)+'</span>'+(p.sev?'<span class="atk '+(p.sev=='치명'||p.sev=='높음'?'l1':'l3')+'">'+esc(p.sev)+'</span>':'')+'<span style="font-size:18px;color:#C7D6EA">'+esc(p.eff)+'</span><div style="font-size:15px;line-height:20px;color:#7C93B2;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(p.title)+' · '+ago(p.ts)+'</div>')},
 kisa:function(k){return A('mini',k.link,'<div class="kt">'+esc(k.title)+'</div><div class="ks">'+(k.date?esc(k.date)+' · ':'')+'KISA 보안공지</div>')},
 events:evHtml
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
function bindSwipe(id,fn){
 var el=$(id),sx=0,sy=0,drag=false;
 el.addEventListener('pointerdown',function(e){sx=e.clientX;sy=e.clientY;drag=true});
 el.addEventListener('pointerup',function(e){
  if(!drag)return;drag=false;
  var dx=e.clientX-sx,dy=e.clientY-sy;
  if(Math.abs(dx)>60&&Math.abs(dx)>Math.abs(dy)*1.5){SUPPRESS=Date.now()+400;fn(dx<0?1:-1)}});
 el.addEventListener('click',function(e){if(Date.now()<SUPPRESS){e.preventDefault();e.stopPropagation()}},true)}
['news','kev','nvd','psirt','kisa','events'].forEach(function(n){
 bindSwipe(n,function(d){nav(n,d)});
 if(AUTO[n]>0)setInterval(function(){nav(n,1)},AUTO[n]*1000)});
bindSwipe('wx',wxnav);
if(AUTO.wx>0)setInterval(function(){wxnav(1)},AUTO.wx*1000);

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
 $('chip').innerHTML='위협 수준<b>'+esc(st.level||'-')+'</b><small>자체 산정</small>';
 countTo($('c1'),st.new2);countTo($('c2'),st.nvd);countTo($('c3'),st.ours7);
 $('c3id').textContent=(st.ours7_ids||[]).join(', ')}

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
 var u=[],nw=(d.news||[]).slice(0,8),kv=(d.kev||[]).slice(0,5),ks=(d.kisa||[]).slice(0,3),ts=todayStr(),i;
 var ev=(d.events||[]).filter(function(e){return (e.kind=='event'||e.kind=='bexco')&&e.end>=ts}).slice(0,2);
 for(i=0;i<nw.length;i++){
  u.push('<span class="ti"><b class="tg2 tgN">뉴스</b>'+esc(nw[i].title)+'</span>');
  if(kv[i])u.push('<span class="ti"><b class="tg2 tgC">CVE</b>'+esc(kv[i].cve)+' '+esc(kv[i].atk)+' · '+esc(kv[i].vendor)+' '+esc(kv[i].product)+'</span>');
  if(ks[i])u.push('<span class="ti"><b class="tg2 tgK">보안공지</b>'+esc(ks[i].title)+'</span>')}
 for(i=0;i<ev.length;i++)u.push('<span class="ti"><b class="tg2 tgE">행사</b>'+md(ev[i].date)+' '+esc(ev[i].title)+'</span>');
 if(!u.length)u.push('<span class="ti">데이터를 불러오는 중입니다</span>');
 setTicker(u.join(''))}

function render(d){
 safe(function(){renderWx(d.weather)});
 LIST.news=(d.news||[]).slice(0,12);
 LIST.kev=(d.kev||[]).slice(0,8);
 LIST.nvd=(d.nvd||[]).slice(0,20);
 LIST.psirt=(d.psirt||[]).slice(0,6);
 LIST.kisa=(d.kisa||[]).slice(0,12);
 LIST.events=d.events||[];
 var lg=(d.ev_log||[]).join(' · ');
 EMPTY.events='<div class="empty">표시할 국내 보안 행사가 없습니다.<br><span style="font-size:15px;color:#7C93B2">수집 결과: '+esc(lg||'기록 없음')+'</span></div>';
 ['news','kev','nvd','psirt','kisa','events'].forEach(function(n){safe(function(){paint(n)})});
 safe(function(){renderStatus(d.stats)});
 safe(function(){buildTicker(d)});
 tick()}

function load(){
 var x=new XMLHttpRequest();x.open('GET','data.json?'+Date.now(),true);
 x.onload=function(){
  try{DATA=JSON.parse(x.responseText)}catch(e){if(window.console)console.log('data.json error',e);return}
  try{render(DATA)}catch(e){if(window.console)console.log('render error',e)}};
 x.send()}
load();setInterval(load,60000);setInterval(tick,1000);tick();
setTimeout(function(){location.reload()},6*3600*1000); /* 6시간마다 전체 새로고침 (TV 브라우저 멈춤 방지) */
</script>
</body>
</html>
"""

if __name__ == "__main__":
    main()
