#!/usr/bin/env python3
"""
cve_poc_collector.py

SCA 도구로 추출한 CVE 리스트를 입력받아, 공개된 PoC/Exploit 참조 정보를
자동으로 수집/정리하는 스크립트.

데이터 소스 (아래 순서로 조회, 앞에서 찾으면 뒤는 건너뜀):
  1. nomi-sec/PoC-in-GitHub  (CVE별 GitHub PoC를 매일 크롤링해 정리한 오픈 리포지토리)
     https://github.com/nomi-sec/PoC-in-GitHub
  2. GitHub Code Search API  (1번에서 못 찾은 CVE에 대한 보조 검색, 선택적, GITHUB_TOKEN 필요)
  3. Exploit-DB              (gitlab.com/exploit-database/exploitdb 저장소의 CSV 인덱스를 로컬에 캐시해두고
                              CVE ID로 매칭. API 제한 없음, 선택적)
  4. NVD References          (NVD API 2.0에서 해당 CVE의 references 중 tags에 "Exploit"이
                              포함된 링크만 추출. 선택적, API 요청 제한 있음)

사용법:
  1) CVE 목록을 텍스트 파일로 준비 (한 줄에 하나, 예: CVE-2021-44228)
       python cve_poc_collector.py --input cve_list.txt --output results.json

  2) GitHub 보조 검색까지 쓰려면 GITHUB_TOKEN 환경변수 설정 후 --use-github-search 추가
       export GITHUB_TOKEN=ghp_xxx
       python cve_poc_collector.py --input cve_list.txt --use-github-search

  3) Exploit-DB까지 쓰려면 --use-exploitdb 추가 (최초 실행 시 CSV 인덱스를 자동 다운로드/캐시)
       python cve_poc_collector.py --input cve_list.txt --use-exploitdb

  4) NVD References까지 쓰려면 --use-nvd 추가. API 키가 있으면 훨씬 빠름(30초당 5건 -> 50건)
       export NVD_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
       python cve_poc_collector.py --input cve_list.txt --use-nvd

  전부 함께 쓰는 예:
       python cve_poc_collector.py --input cve_list.txt --output results.json \
           --use-github-search --use-exploitdb --use-nvd

출력:
  results.json  - CVE별 매칭된 PoC/Exploit 참조 목록(URL, star 수, 설명, 출처 등)
  results.csv   - 스프레드시트로 보기 편한 요약본

주의:
  이 스크립트는 "PoC/Exploit 참조가 어디 있는지 찾아 목록화"만 합니다.
  실제 코드 내용을 받아 실행하기 전에는 반드시 사람이 직접 읽고 검토하세요
  (일부 공개 PoC 저장소/Exploit-DB 항목에는 악성 코드나 잘못된 코드가 섞여 있을 수 있습니다).
"""

import argparse
import csv
import io
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

NOMI_SEC_BASE = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# NVD 요청 제한: API 키 없으면 30초당 5건, 있으면 30초당 50건.
# 여유를 두고 각각 6.5초 / 0.7초 간격을 둔다.
NVD_DELAY_NO_KEY = 6.5
NVD_DELAY_WITH_KEY = 0.7


def load_cve_list(path):
    """텍스트 파일에서 CVE ID를 추출 (형식이 섞여 있어도 정규식으로 걸러냄)."""
    cves = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            match = CVE_PATTERN.search(line)
            if match:
                cves.append(match.group(0).upper())
    # 중복 제거, 순서 유지
    seen = set()
    unique = []
    for c in cves:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique


def fetch_raw(url, headers=None, retries=3, backoff=2):
    """재시도 로직을 포함한 GET 요청. 응답 바이트를 그대로 반환 (JSON/CSV 공용)."""
    req = urllib.request.Request(url, headers=headers or {})
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # 대상 리소스 없음
            if e.code == 429:
                print(f"  [경고] HTTP 429 (rate limit): {url} - 대기 후 재시도", file=sys.stderr)
                time.sleep(backoff * attempt * 3)
                continue
            if e.code == 403:
                print(f"  [경고] HTTP 403 (rate limit 가능성): {url}", file=sys.stderr)
                return None
            if attempt == retries:
                print(f"  [오류] {url} -> {e}", file=sys.stderr)
                return None
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == retries:
                print(f"  [오류] {url} -> {e}", file=sys.stderr)
                return None
        time.sleep(backoff * attempt)
    return None


def fetch_json(url, headers=None, retries=3, backoff=2):
    raw = fetch_raw(url, headers=headers, retries=retries, backoff=backoff)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"  [오류] JSON 파싱 실패: {url} -> {e}", file=sys.stderr)
        return None


def fetch_text(url, headers=None, retries=3, backoff=2):
    raw = fetch_raw(url, headers=headers, retries=retries, backoff=backoff)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def query_nomi_sec(cve_id):
    """
    nomi-sec/PoC-in-GitHub 은 연도별 디렉토리에 CVE-YYYY-NNNNN.json 파일로
    PoC 저장소 목록을 저장해둠. 해당 파일을 직접 raw로 가져온다.
    """
    year_match = re.match(r"CVE-(\d{4})-", cve_id)
    if not year_match:
        return []
    year = year_match.group(1)
    url = f"{NOMI_SEC_BASE}/{year}/{cve_id}.json"
    data = fetch_json(url)
    if not data:
        return []

    results = []
    for entry in data:
        results.append({
            "source": "nomi-sec/PoC-in-GitHub",
            "repo_url": entry.get("html_url"),
            "description": entry.get("description"),
            "stars": entry.get("stargazers_count"),
            "created_at": entry.get("created_at"),
        })
    return results


def query_github_search(cve_id, token):
    """GitHub 저장소 검색 API로 CVE ID를 이름/설명에 포함한 저장소를 보조 검색."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
    }
    query = urllib.parse.quote(f"{cve_id} in:name,description,readme")
    url = f"{GITHUB_SEARCH_API}?q={query}&sort=stars&order=desc&per_page=5"
    data = fetch_json(url, headers=headers)
    if not data or "items" not in data:
        return []

    results = []
    for item in data["items"]:
        results.append({
            "source": "github-search",
            "repo_url": item.get("html_url"),
            "description": item.get("description"),
            "stars": item.get("stargazers_count"),
            "created_at": item.get("created_at"),
        })
    return results


def load_exploitdb_index(cache_path, force_refresh=False):
    """
    offensive-security/exploitdb 저장소의 files_exploits.csv를 로컬에 캐시하고,
    CVE ID -> [해당 exploit-db row, ...] 매핑을 만들어 반환한다.
    (CSV의 'codes' 컬럼에 세미콜론으로 구분된 CVE-YYYY-NNNNN 값들이 들어있음)
    """
    text = None
    if not force_refresh and os.path.exists(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                text = f.read()
        except OSError:
            text = None

    if text is None:
        print(f"  [정보] Exploit-DB 인덱스 다운로드 중... ({EXPLOITDB_CSV_URL})", file=sys.stderr)
        text = fetch_text(EXPLOITDB_CSV_URL)
        if text is None:
            print("  [경고] Exploit-DB 인덱스를 받지 못했습니다. --use-exploitdb 결과 없이 진행합니다.",
                  file=sys.stderr)
            return None
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(text)
        except OSError as e:
            print(f"  [경고] Exploit-DB 인덱스 캐시 저장 실패: {e}", file=sys.stderr)

    index = {}
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        codes = row.get("codes") or ""
        for code in codes.split(";"):
            code = code.strip().upper()
            if CVE_PATTERN.fullmatch(code):
                index.setdefault(code, []).append(row)
    return index


def query_exploitdb(cve_id, exploitdb_index):
    if not exploitdb_index:
        return []
    rows = exploitdb_index.get(cve_id.upper(), [])
    results = []
    for row in rows:
        edb_id = row.get("id", "").strip()
        if not edb_id:
            continue
        results.append({
            "source": "exploit-db",
            "repo_url": f"https://www.exploit-db.com/exploits/{edb_id}",
            "description": row.get("description"),
            "stars": None,
            "created_at": row.get("date_added"),
        })
    return results


def query_nvd(cve_id, api_key=None):
    """
    NVD API 2.0에서 CVE 상세 정보를 조회하고, references 중 tags에
    'Exploit'이 포함된 것만 골라 반환한다 (벤더 어드바이저리 등 잡음 제거).
    """
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_API_BASE}?cveId={cve_id}"
    data = fetch_json(url, headers=headers)
    if not data:
        return []

    vulns = data.get("vulnerabilities") or []
    if not vulns:
        return []

    cve_data = vulns[0].get("cve", {})
    results = []
    for ref in cve_data.get("references", []):
        tags = ref.get("tags", []) or []
        if any(t.lower() == "exploit" for t in tags):
            results.append({
                "source": "nvd-references",
                "repo_url": ref.get("url"),
                "description": f"NVD reference tags: {', '.join(tags)}" if tags else "NVD reference",
                "stars": None,
                "created_at": None,
            })
    return results


def collect(cve_list, use_github_search=False, github_token=None,
            use_exploitdb=False, exploitdb_index=None,
            use_nvd=False, nvd_api_key=None,
            sleep_sec=0.5):
    all_results = {}
    total = len(cve_list)
    nvd_delay = NVD_DELAY_WITH_KEY if nvd_api_key else NVD_DELAY_NO_KEY

    for idx, cve_id in enumerate(cve_list, start=1):
        print(f"[{idx}/{total}] {cve_id} 조회 중...")
        pocs = query_nomi_sec(cve_id)

        if not pocs and use_github_search and github_token:
            pocs = query_github_search(cve_id, github_token)

        if not pocs and use_exploitdb and exploitdb_index is not None:
            pocs = query_exploitdb(cve_id, exploitdb_index)

        if not pocs and use_nvd:
            pocs = query_nvd(cve_id, nvd_api_key)
            time.sleep(nvd_delay)  # NVD 레이트리밋 준수 (다른 소스와 별개 딜레이)

        all_results[cve_id] = {
            "poc_count": len(pocs),
            "pocs": pocs,
        }

        # API 예의상 약간의 딜레이 (특히 GitHub API rate limit 방지)
        time.sleep(sleep_sec)

    return all_results


def write_json(results, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)


def write_csv(results, path):
    with open(path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["CVE", "PoC 개수", "저장소/참조 URL", "Star 수", "출처", "설명"])
        for cve_id, data in results.items():
            if not data["pocs"]:
                writer.writerow([cve_id, 0, "", "", "", "매칭된 PoC 없음"])
                continue
            for poc in data["pocs"]:
                writer.writerow([
                    cve_id,
                    data["poc_count"],
                    poc.get("repo_url", ""),
                    poc.get("stars", ""),
                    poc.get("source", ""),
                    (poc.get("description") or "").replace("\n", " "),
                ])


def print_summary(results):
    total = len(results)
    found = sum(1 for v in results.values() if v["poc_count"] > 0)

    by_source = {}
    for v in results.values():
        for poc in v["pocs"]:
            src = poc.get("source", "unknown")
            by_source[src] = by_source.get(src, 0) + 1

    print("\n" + "=" * 50)
    print(f"총 CVE 수: {total}")
    print(f"PoC/참조 매칭된 CVE 수: {found}")
    print(f"미매칭 CVE 수: {total - found}")
    if by_source:
        print("\n[출처별 항목 수]")
        for src, cnt in sorted(by_source.items(), key=lambda x: -x[1]):
            print(f"  - {src}: {cnt}건")
    print("=" * 50)
    if total - found > 0:
        print("\n[미매칭 CVE 목록] (수동 확인 권장)")
        for cve_id, data in results.items():
            if data["poc_count"] == 0:
                print(f"  - {cve_id}")


def main():
    parser = argparse.ArgumentParser(description="SCA로 추출한 CVE 리스트에서 PoC/Exploit 참조 정보 수집")
    parser.add_argument("--input", required=True, help="CVE 목록 텍스트 파일 경로")
    parser.add_argument("--output", default="results.json", help="결과 JSON 저장 경로 (기본: results.json)")
    parser.add_argument("--csv", default="results.csv", help="결과 CSV 저장 경로 (기본: results.csv)")
    parser.add_argument("--use-github-search", action="store_true",
                         help="nomi-sec에서 못 찾은 CVE에 대해 GitHub 검색 API로 보조 검색 (GITHUB_TOKEN 필요)")
    parser.add_argument("--use-exploitdb", action="store_true",
                         help="위 소스들에서 못 찾은 CVE에 대해 Exploit-DB CSV 인덱스로 보조 검색")
    parser.add_argument("--exploitdb-cache", default="exploitdb_files_exploits.csv",
                         help="Exploit-DB CSV 인덱스 캐시 경로 (기본: exploitdb_files_exploits.csv)")
    parser.add_argument("--refresh-exploitdb", action="store_true",
                         help="캐시된 Exploit-DB 인덱스가 있어도 다시 다운로드")
    parser.add_argument("--use-nvd", action="store_true",
                         help="위 소스들에서 못 찾은 CVE에 대해 NVD API references(tag=Exploit)로 보조 검색")
    parser.add_argument("--nvd-api-key", default=None,
                         help="NVD API 키 (없으면 NVD_API_KEY 환경변수 사용, 없으면 무키로 진행 - 느림)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[오류] 입력 파일을 찾을 수 없습니다: {args.input}", file=sys.stderr)
        sys.exit(1)

    cve_list = load_cve_list(args.input)
    if not cve_list:
        print("[오류] 입력 파일에서 CVE ID를 찾지 못했습니다.", file=sys.stderr)
        sys.exit(1)

    print(f"총 {len(cve_list)}개의 CVE를 발견했습니다.\n")

    github_token = os.environ.get("GITHUB_TOKEN")
    if args.use_github_search and not github_token:
        print("[경고] --use-github-search 옵션을 사용했지만 GITHUB_TOKEN 환경변수가 없습니다. "
              "보조 검색은 건너뜁니다.", file=sys.stderr)

    exploitdb_index = None
    if args.use_exploitdb:
        exploitdb_index = load_exploitdb_index(args.exploitdb_cache, force_refresh=args.refresh_exploitdb)

    nvd_api_key = args.nvd_api_key or os.environ.get("NVD_API_KEY")
    if args.use_nvd and not nvd_api_key:
        print("[경고] --use-nvd 옵션을 사용했지만 NVD API 키가 없습니다. "
              f"무키로 진행합니다 (요청 간 {NVD_DELAY_NO_KEY}초 대기, 느림).", file=sys.stderr)

    results = collect(
        cve_list,
        use_github_search=args.use_github_search,
        github_token=github_token,
        use_exploitdb=args.use_exploitdb,
        exploitdb_index=exploitdb_index,
        use_nvd=args.use_nvd,
        nvd_api_key=nvd_api_key,
    )

    write_json(results, args.output)
    write_csv(results, args.csv)
    print_summary(results)

    print(f"\n결과 저장 완료: {args.output}, {args.csv}")


if __name__ == "__main__":
    main()
