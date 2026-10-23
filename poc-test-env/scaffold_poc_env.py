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
"""

import argparse
import os
import re
import shutil
import stat
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


def scaffold(cve_id, language, package, version, runtime_version):
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
    with open(os.path.join(target_dir, "RESULT_NOTES.md"), "w", encoding="utf-8") as f:
        f.write(notes_content)

    # ---- placeholder README ----
    readme_content = f"""# {cve_id} 테스트 환경

생성됨: scaffold_poc_env.py
언어: {language} ({version_arg}={runtime_version})
컴포넌트: {package or '(미지정)'} {version or ''}

## 다음 단계
1. src/app/ 에 PoC 앱 코드(또는 최소 재현 코드)를 넣으세요.
2. poc-scripts/ 에 공격 스크립트를 넣으세요.
   ⚠️ 실행 전 반드시 코드를 사람이 읽고 검토하세요.
3. 실행: `./run.sh {cve_id}`
4. 검증 결과는 RESULT_NOTES.md 에 기록하세요.
"""
    with open(os.path.join(target_dir, "README.md"), "w", encoding="utf-8") as f:
        f.write(readme_content)

    print(f"[완료] {target_dir} 생성됨")
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
    parser.add_argument("--package", help="취약 패키지명 (예: org.apache.logging.log4j:log4j-core)")
    parser.add_argument("--version", help="취약 버전 (예: 2.14.1)")
    parser.add_argument("--jdk", dest="runtime_version", help="JDK 버전 (java 선택 시)")
    parser.add_argument("--python-version", dest="runtime_version", help="Python 버전 (python 선택 시)")
    parser.add_argument("--node-version", dest="runtime_version", help="Node 버전 (node 선택 시)")

    args = parser.parse_args()
    scaffold(args.cve_id, args.language, args.package, args.version, args.runtime_version)


if __name__ == "__main__":
    main()
