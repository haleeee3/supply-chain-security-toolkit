#!/usr/bin/env python3
"""
scaffold_poc_env.py

CVE ID와 언어(java/python/node)를 입력받아, templates/ 아래의 표준 템플릿을
poc/{CVE-ID}/ 디렉토리로 복사·치환해서 새 테스트 환경을 즉시 생성합니다.

사용법:
  python3 scaffold_poc_env.py CVE-2021-44228 java \
      --package "org.apache.logging.log4j:log4j-core" \
      --version "2.14.1" \
      --jdk 8

  python3 scaffold_poc_env.py CVE-2022-25845 python \
      --package "fastjson-like-example" \
      --version "1.2.3" \
      --python-version 3.9

  # PoC 자동 clone + 재현 우선순위 포함
  python3 scaffold_poc_env.py CVE-2023-4863 python \
      --package "Pillow" --version "8.0.0" \
      --auto-clone --poc-results results.json \
      --epss 0.9998 --cvss 8.8

생성 결과 (poc/{CVE-ID}/):
  Dockerfile              - 언어별 템플릿에서 값 치환 완료
  docker-compose.yml      - 격리 네트워크 구성 (internal: true)
  run.sh                  - 표준 실행 스크립트 (실행 권한 자동 부여)
  RESULT_NOTES.md         - 검증 결과 및 VEX 판단 기록용 노트
  src/                    - PoC 앱 코드를 넣을 빈 디렉토리
  poc-scripts/            - PoC 스크립트(공격 스크립트)를 넣을 빈 디렉토리

이후 사람이 직접:
  1) src/ 에 PoC 저장소 코드(또는 최소 재현 앱)를 넣고
  2) poc-scripts/ 에 공격 스크립트를 넣고 (실행 전 반드시 코드 검토!)
  3) ./run.sh {CVE-ID} 로 격리 환경에서 실행
  4) 재현 결과를 RESULT_NOTES.md 에 기록하고 VEX 최종 판단
"""

import argparse
import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(SCRIPT_DIR, "templates")
POC_ROOT = os.path.join(SCRIPT_DIR, "poc")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$", re.IGNORECASE)

LANGUAGE_DEFAULTS = {
    "java": {"version_arg": "JDK_VERSION", "default_version": "8"},
    "python": {"version_arg": "PYTHON_VERSION", "default_version": "3.10"},
    "node": {"version_arg": "NODE_VERSION", "default_version": "18"},
}


def validate_cve(cve_id):
    if not CVE_PATTERN.match(cve_id):
        print(f"[오류] CVE ID 형식이 올바르지 않습니다: {cve_id}", file=sys.stderr)
        sys.exit(1)
    return cve_id.upper()


def render_template(text, replacements):
    for key, value in replacements.items():
        text = text.replace(key, value)
    return text


def determine_verification_priority(epss_score=None, has_poc=False, cvss_score=None):
    """
    VEX 초안이 아닌 재현 검증 우선순위 판단.
    실제 VEX(affected/not_affected)는 재현 검증 후 사람이 직접 결정해야 함.

    반환값: (priority, reason, recommended_action)
    """
    epss = float(epss_score) if epss_score else 0.0
    cvss = float(cvss_score) if cvss_score else 0.0

    if has_poc and epss > 0.5:
        return (
            "HIGH",
            f"공개 PoC 존재 + EPSS {epss*100:.1f}% (50% 초과)",
            "즉시 재현 검증 수행 후 VEX 판단"
        )
    elif has_poc and epss > 0.1:
        return (
            "MEDIUM",
            f"공개 PoC 존재 + EPSS {epss*100:.1f}% (10% 초과)",
            "재현 검증 권고 후 VEX 판단"
        )
    elif has_poc:
        return (
            "MEDIUM",
            "공개 PoC 존재 (EPSS 낮음)",
            "PoC 코드 검토 후 재현 검증 필요"
        )
    elif epss > 0.5:
        return (
            "MEDIUM",
            f"EPSS {epss*100:.1f}% (50% 초과), PoC 미확인",
            "PoC 추가 탐색 및 재현 검증 필요"
        )
    elif cvss >= 9.0:
        return (
            "MEDIUM",
            f"CVSS {cvss} (Critical), PoC 미확인",
            "추가 분석 및 모니터링 필요"
        )
    else:
        return (
            "LOW",
            "PoC 없음, EPSS 낮음",
            "모니터링 유지, 패치 일정 검토"
        )


def clone_poc_repos(target_dir, poc_results_path, cve_id, max_clone=2):
    """
    cve_poc_collector.py 결과(results.json)에서
    해당 CVE의 PoC 저장소를 자동으로 clone.
    """
    if not os.path.exists(poc_results_path):
        print(f"  [경고] PoC 결과 파일 없음: {poc_results_path}")
        return False, 0

    with open(poc_results_path, "r", encoding="utf-8") as f:
        results = json.load(f)

    cve_data = results.get(cve_id.upper(), {})
    pocs = cve_data.get("pocs", [])

    # GitHub 저장소만 필터링 (cisa-kev, nvd-references 제외)
    github_pocs = [
        p for p in pocs
        if p.get("repo_url")
        and "github.com" in p.get("repo_url", "")
        and p.get("source") not in ["cisa-kev", "nvd-references"]
    ]

    if not github_pocs:
        print("  [정보] clone 가능한 PoC 저장소 없음")
        return False, 0

    src_dir = os.path.join(target_dir, "src")
    cloned = 0

    for poc in github_pocs[:max_clone]:
        repo_url = poc.get("repo_url")
        repo_name = repo_url.rstrip("/").split("/")[-1]
        clone_path = os.path.join(src_dir, repo_name)

        print(f"  [clone] {repo_url}")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", repo_url, clone_path],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                print(f"  [완료] {repo_name} clone 성공")
                cloned += 1
            else:
                print(f"  [경고] clone 실패: {result.stderr.strip()}")
        except subprocess.TimeoutExpired:
            print(f"  [경고] clone 시간 초과: {repo_url}")
        except Exception as e:
            print(f"  [경고] clone 오류: {e}")

    return cloned > 0, cloned


def scaffold(cve_id, language, package, version, runtime_version,
             auto_clone=False, poc_results_path=None,
             epss_score=None, cvss_score=None):

    cve_id = validate_cve(cve_id)
    if language not in LANGUAGE_DEFAULTS:
        print(f"[오류] 지원하지 않는 언어: {language} (java/python/node 중 선택)", file=sys.stderr)
        sys.exit(1)

    target_dir = os.path.join(POC_ROOT, cve_id)
    if os.path.exists(target_dir):
        print(f"[오류] 이미 존재하는 디렉토리입니다: {target_dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(target_dir)
    os.makedirs(os.path.join(target_dir, "src", "app"))
    os.makedirs(os.path.join(target_dir, "poc-scripts"))

    lang_defaults = LANGUAGE_DEFAULTS[language]
    version_arg = lang_defaults["version_arg"]
    runtime_version = runtime_version or lang_defaults["default_version"]

    replacements = {
        "CVE-YYYY-NNNNN": cve_id,
        "group:artifact": package or "unknown",
        "package-name": package or "unknown",
        "0.0.0": version or "unknown",
    }

    # ---- Dockerfile ----
    dockerfile_template_path = os.path.join(TEMPLATES_DIR, language, "Dockerfile.template")
    with open(dockerfile_template_path, "r", encoding="utf-8") as f:
        dockerfile_content = f.read()
    dockerfile_content = render_template(dockerfile_content, replacements)
    dockerfile_content = re.sub(
        rf"ARG {version_arg}=\S+",
        f"ARG {version_arg}={runtime_version}",
        dockerfile_content,
    )
    with open(os.path.join(target_dir, "Dockerfile"), "w", encoding="utf-8") as f:
        f.write(dockerfile_content)

    # ---- docker-compose.yml ----
    compose_template_path = os.path.join(TEMPLATES_DIR, "docker-compose.template.yml")
    with open(compose_template_path, "r", encoding="utf-8") as f:
        compose_content = f.read()
    with open(os.path.join(target_dir, "docker-compose.yml"), "w", encoding="utf-8") as f:
        f.write(compose_content)

    # ---- run.sh ----
    run_sh_template_path = os.path.join(TEMPLATES_DIR, "run.sh.template")
    with open(run_sh_template_path, "r", encoding="utf-8") as f:
        run_sh_content = f.read()
    run_sh_path = os.path.join(target_dir, "run.sh")
    with open(run_sh_path, "w", encoding="utf-8") as f:
        f.write(run_sh_content)
    st = os.stat(run_sh_path)
    os.chmod(run_sh_path, st.st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    # ---- PoC 자동 clone ----
    has_poc = False
    cloned_count = 0

    if poc_results_path and os.path.exists(poc_results_path):
        with open(poc_results_path, "r", encoding="utf-8") as f:
            poc_data = json.load(f)
        cve_poc_info = poc_data.get(cve_id.upper(), {})
        has_poc = cve_poc_info.get("poc_count", 0) > 0

        if auto_clone and has_poc:
            print("\n[PoC 자동 clone 시작]")
            has_poc, cloned_count = clone_poc_repos(
                target_dir, poc_results_path, cve_id
            )
            if cloned_count > 0:
                print(f"  → {cloned_count}개 저장소 clone 완료")
            else:
                print("  → clone된 저장소 없음")

    # ---- 재현 검증 우선순위 판단 ----
    priority, reason, recommended_action = determine_verification_priority(
        epss_score=epss_score,
        has_poc=has_poc,
        cvss_score=cvss_score
    )

    # ---- RESULT_NOTES.md ----
    notes_template_path = os.path.join(TEMPLATES_DIR, "RESULT_NOTES.template.md")
    with open(notes_template_path, "r", encoding="utf-8") as f:
        notes_content = f.read()
    notes_content = notes_content.replace("{CVE-ID}", cve_id)
    if package:
        notes_content = notes_content.replace(
            "- 대상 컴포넌트/버전:",
            f"- 대상 컴포넌트/버전: {package} {version or ''}".rstrip(),
        )

    priority_section = f"""
## 재현 검증 우선순위 (자동 생성)

| 항목 | 값 |
|------|-----|
| CVE ID | {cve_id} |
| 검증 우선순위 | **{priority}** |
| 판단 근거 | {reason} |
| 권고 조치 | {recommended_action} |
| EPSS 점수 | {epss_score or 'N/A'} |
| CVSS 점수 | {cvss_score or 'N/A'} |
| PoC 존재 여부 | {'✅ 있음' if has_poc else '❌ 없음 (추가 탐색 필요)'} |
| clone된 저장소 수 | {cloned_count}개 |
| 생성 일시 | {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |

## VEX 최종 판단 (재현 검증 후 사람이 직접 작성)

> ⚠️ 아래 항목은 실제 재현 검증 후 사람이 직접 판단하여 작성하세요.
> 자동 생성된 우선순위는 참고용이며, VEX 상태는 재현 결과에 따라 결정됩니다.

| 항목 | 값 |
|------|-----|
| VEX 상태 | [ ] affected / [ ] not_affected / [ ] under_investigation / [ ] fixed |
| 재현 성공 여부 | |
| 실제 영향 범위 | |
| 최종 판단자 | |
| 판단 일시 | |
| 비고 | |
"""
    notes_content += priority_section

    with open(os.path.join(target_dir, "RESULT_NOTES.md"), "w", encoding="utf-8") as f:
        f.write(notes_content)

    # ---- placeholder README ----
    readme_content = f"""# {cve_id} 테스트 환경

생성됨: scaffold_poc_env.py
언어: {language} ({version_arg}={runtime_version})
컴포넌트: {package or '(미지정)'} {version or ''}
재현 검증 우선순위: {priority}

## 다음 단계
1. src/app/ 에 PoC 앱 코드(또는 최소 재현 코드)를 넣으세요.
2. poc-scripts/ 에 공격 스크립트를 넣으세요.
   ⚠️ 실행 전 반드시 코드를 사람이 읽고 검토하세요.
3. 실행: `./run.sh {cve_id}`
4. 재현 결과를 RESULT_NOTES.md 에 기록하고 VEX 최종 판단을 완료하세요.
"""
    with open(os.path.join(target_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)

    print(f"[완료] {target_dir} 생성됨")
    print(f"재현 검증 우선순위: {priority} - {reason}")
    print("구조:")
    for root, dirs, files in os.walk(target_dir):
        level = root.replace(target_dir, "").count(os.sep)
        indent = "  " * level
        print(f"{indent}{os.path.basename(root)}/")
        for fname in files:
            print(f"{indent}  {fname}")


def main():
    parser = argparse.ArgumentParser(
        description="CVE ID/언어를 입력받아 표준 PoC 테스트 환경을 자동 생성"
    )
    parser.add_argument("cve_id", help="예: CVE-2021-44228")
    parser.add_argument("language", choices=["java", "python", "node"], help="애플리케이션 언어")
    parser.add_argument("--package", help="취약 패키지명")
    parser.add_argument("--version", help="취약 버전")
    parser.add_argument("--jdk", dest="runtime_version", help="JDK 버전 (java 선택 시)")
    parser.add_argument("--python-version", dest="runtime_version", help="Python 버전 (python 선택 시)")
    parser.add_argument("--node-version", dest="runtime_version", help="Node 버전 (node 선택 시)")
    parser.add_argument("--auto-clone", action="store_true",
                        help="PoC 저장소 자동 clone (--poc-results 필요)")
    parser.add_argument("--poc-results", default=None,
                        help="cve_poc_collector.py 결과 JSON 경로 (예: results.json)")
    parser.add_argument("--epss", default=None,
                        help="EPSS 점수 (예: 0.9998)")
    parser.add_argument("--cvss", default=None,
                        help="CVSS 점수 (예: 8.8)")

    args = parser.parse_args()
    scaffold(
        args.cve_id,
        args.language,
        args.package,
        args.version,
        args.runtime_version,
        auto_clone=args.auto_clone,
        poc_results_path=args.poc_results,
        epss_score=args.epss,
        cvss_score=args.cvss,
    )


if __name__ == "__main__":
    main()