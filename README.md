# supply-chain-security-toolkit

공급망 보안(Supply Chain Security) 업무를 위한 
CVE 분석·PoC 재현 검증·VEX 도출 자동화 도구 모음입니다.

SCA 도구로 도출된 CVE를 단순히 목록화하는 것을 넘어,
실제 익스플로잇 가능 여부를 검증하고
VEX(Vulnerability Exploitability eXchange) 판단 근거를
문서화하는 전 과정을 지원합니다.

---

## 도구 목록

### 1. cve_poc_collector.py
CVE ID 목록을 입력받아 공개된 PoC 저장소를 자동 수집합니다.

**데이터 소스**
- nomi-sec/PoC-in-GitHub
- GitHub Search API

**사용법**
```bash
python cve_poc_collector.py --input cve_list.txt --output results.json
```

**출력**
- `results.json` — CVE별 PoC 저장소 링크, star 수, 출처
- `results.csv` — 스프레드시트용 요약본

---

### 2. scaffold_poc_env.py
CVE ID와 언어를 입력받아 Docker 기반 격리 재현 환경을
자동으로 생성합니다.

**지원 언어**
- Java / Python / Node.js

**사용법**
```bash
python poc-test-env/scaffold_poc_env.py CVE-2021-44228 java \
    --package "org.apache.logging.log4j:log4j-core" \
    --version "2.14.1" \
    --jdk 8
```

**생성 결과**
```
poc/{CVE-ID}/
├── Dockerfile          # 취약 버전 환경 설정
├── docker-compose.yml  # 격리 네트워크 구성 (internal: true)
├── run.sh              # 표준 실행 스크립트
└── RESULT_NOTES.md     # 재현 결과 및 VEX 판단 기록 양식
```

---

### 3. poc-test-env/ (템플릿 세트)
CVE별 격리 재현 환경의 표준 템플릿입니다.

- 네트워크 격리 (`internal: true`) 기본 적용
- 최소 권한 계정 실행
- 재현 결과 → Reachability 판단 → VEX 상태까지
  이어지는 기록 양식 포함

---

## 워크플로우

```
SCA 도구로 CVE 목록 도출
        ↓
cve_poc_collector.py
(PoC 저장소 자동 수집)
        ↓
PoC 코드 사전 검토 (사람이 직접)
        ↓
scaffold_poc_env.py
(격리 재현 환경 자동 생성)
        ↓
Docker 격리 환경에서 재현 검증
        ↓
RESULT_NOTES.md 기록
→ VEX 판단 (affected / not_affected)
```

---

## 재현 검증 사례

| CVE | 대상 | 유형 | 재현 결과 | VEX |
|---|---|---|---|---|
| CVE-2025-66516 | Apache Tika | XXE | 성공 (환경 B) | affected |
| CVE-2025-48976 | Commons FileUpload | DoS | 조건부 | not_affected |
| CVE-2025-30359 | webpack-dev-server | 소스코드 탈취 | 성공 | affected |
| CVE-2025-48924 | Commons Lang | StackOverflow | 성공 | affected |
| CVE-2025-0167 | curl | 자격증명 유출 | 성공 | affected |

---

## 참고 문서

- [CWE Top 25 분석 가이드](./docs/cwe-top25-consulting.md)
- [VEX 스펙 정리](./docs/vex-spec-guide.md)

---

## 주의사항

이 도구들은 **방어 목적의 취약점 검증**을 위해 제작되었습니다.
- 모든 PoC 실행은 격리된 로컬 환경에서만 수행하세요
- 실제 운영 환경이나 타인의 시스템에 사용하지 마세요
- PoC 코드는 실행 전 반드시 사람이 직접 검토하세요
