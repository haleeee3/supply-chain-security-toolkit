# 2025 CWE Top 25 요약 — 컨설팅 참고용

> 출처: MITRE/CISA, 2025년 12월 발표 (2024.6~2025.6 발생 CVE 39,080건 분석 기준)
> 목적: SCA 결과로 CVE를 받았을 때 "이게 대략 어떤 유형이고 왜 위험한지" 빠르게 감을 잡기 위한 참고표. 코드 작성 능력이 아니라 **패턴 인식**이 목표입니다.

---

## 사용법

CVE 리포트를 받으면 NVD나 SCA 도구 결과에 매핑된 **CWE-ID**가 함께 표기되는 경우가 대부분입니다. 이 표에서 해당 CWE-ID를 찾아 "왜 위험한지 / 뭘 확인해야 하는지 / 고객에게 뭐라고 설명하면 되는지"를 참고하세요.

---

## Top 10 (가장 자주 마주치게 될 유형)

| 순위 | CWE | 이름 | 한줄 설명 | 컨설팅 시 확인 포인트 |
|---|---|---|---|---|
| 1 | CWE-79 | XSS (교차 사이트 스크립팅) | 사용자 입력이 그대로 웹 페이지에 출력되어 악성 스크립트 실행 | 출력 시 이스케이프 처리 여부, 프레임워크 자동 이스케이프 사용 여부 |
| 2 | CWE-89 | SQL Injection | 사용자 입력이 SQL 쿼리에 그대로 삽입됨 | Prepared Statement / ORM 사용 여부 (문자열 조립 쿼리인지가 핵심) |
| 3 | CWE-352 | CSRF | 사용자 의도 없이 위조된 요청이 실행됨 | CSRF 토큰 검증 로직 존재 여부 |
| 4 | CWE-862 | Missing Authorization | 인증은 됐지만 "이 리소스에 접근할 권한이 있는지" 검사 누락 | 로그인 여부만 확인하고 소유권/역할 확인 로직이 빠졌는지 |
| 5 | CWE-787 | Out-of-bounds Write | 메모리 경계를 벗어난 쓰기 (C/C++ 계열에서 주로 발생) | 개발 언어가 메모리 관리 언어(C/C++)인지 우선 확인 — Java/Python/Node 앱이면 대개 해당 없음(라이브러리 네이티브 모듈 제외) |
| 6 | CWE-22 | Path Traversal | 파일 경로에 `../` 등을 넣어 의도치 않은 경로 접근 | 파일 업로드/다운로드 기능에서 사용자 입력을 경로에 그대로 사용하는지 |
| 7 | CWE-416 | Use After Free | 해제된 메모리를 참조 (C/C++ 계열) | 위와 동일 — 메모리 관리 언어 여부 우선 확인 |
| 8 | CWE-125 | Out-of-bounds Read | 메모리 경계를 벗어난 읽기 (C/C++ 계열) | 위와 동일 |
| 9 | CWE-78 | OS Command Injection | 사용자 입력이 OS 명령어 실행에 그대로 사용됨 | `exec`, `system`, `Runtime.exec` 등 호출부에 사용자 입력이 섞이는지 |
| 10 | CWE-94 | Code Injection | 사용자 입력이 코드로 해석되어 실행됨 (예: `eval`) | `eval`, 템플릿 엔진의 SSTI(서버사이드 템플릿 인젝션) 가능성 |

---

## 11~25위 (자주는 아니지만 종종 등장)

| 순위 | CWE | 이름 | 한줄 설명 |
|---|---|---|---|
| 11 | CWE-120 | Classic Buffer Overflow | 입력 크기를 검사하지 않고 버퍼에 복사 (C/C++) |
| 12 | CWE-434 | Unrestricted File Upload | 실행 가능한 파일(.jsp, .php 등)의 업로드를 막지 않음 |
| 13 | CWE-476 | NULL Pointer Dereference | NULL 값 미검사로 인한 크래시 |
| 14 | CWE-121 | Stack-based Buffer Overflow | 스택 버퍼 오버플로우 (C/C++) |
| 15 | CWE-502 | **Deserialization of Untrusted Data** | 신뢰할 수 없는 데이터를 역직렬화 — Java(`ObjectInputStream`), Python(`pickle`) 앱에서 특히 위험, RCE로 직결되는 경우 많음 |
| 16 | CWE-122 | Heap-based Buffer Overflow | 힙 버퍼 오버플로우 (C/C++) |
| 17 | CWE-863 | Incorrect Authorization | 권한 검사 로직은 있지만 잘못 구현됨 |
| 18 | CWE-20 | Improper Input Validation | 입력값 검증 전반의 미비 (포괄적 카테고리) |
| 19 | CWE-284 | Improper Access Control | 접근 제어 전반의 미비 (포괄적 카테고리) |
| 20 | CWE-200 | Exposure of Sensitive Information | 에러 메시지, 로그 등을 통한 민감정보 노출 |
| 21 | CWE-306 | Missing Authentication for Critical Function | 중요 기능에 인증 자체가 없음 |
| 22 | CWE-918 | **SSRF** (서버 측 요청 위조) | 서버가 사용자 입력 URL로 임의 요청을 보냄 — 내부망 접근/클라우드 메타데이터 탈취로 이어질 수 있음 |
| 23 | CWE-77 | Command Injection | OS Command Injection(CWE-78)의 상위/일반 카테고리 |
| 24 | CWE-639 | Authorization Bypass Through User-Controlled Key | 사용자가 조작 가능한 ID/키로 타인의 리소스에 접근 (IDOR과 유사) |
| 25 | CWE-770 | Allocation of Resources Without Limits | 리소스 제한 없는 할당 — DoS로 이어짐 |

---

## 웹 애플리케이션 컨설팅에서 특히 자주 보게 될 카테고리 (우선 학습 추천)

개발 언어가 Java/Python/Node 계열이라면, 메모리 안전성 관련 항목(Out-of-bounds Write/Read, Use After Free, Buffer Overflow류)은 대부분 해당 사항이 없는 경우가 많습니다 (네이티브 확장 모듈 사용 시는 예외). 대신 아래 항목에 집중하는 게 효율적입니다.

- **Injection 계열**: CWE-79(XSS), CWE-89(SQLi), CWE-78(OS Command Injection), CWE-94(Code Injection)
- **인증/인가 계열**: CWE-862(Missing Authorization), CWE-863(Incorrect Authorization), CWE-639(IDOR 유사), CWE-306(Missing Authentication)
- **역직렬화**: CWE-502 — Java/Python 생태계에서 RCE로 직결되는 대표적 사례 (예: Log4Shell, Fastjson, PyYAML 등)
- **SSRF**: CWE-918 — 클라우드 환경(AWS/GCP 메타데이터 엔드포인트 등)에서 특히 치명적

---

## 참고 자료
- MITRE CWE Top 25 공식 페이지: https://cwe.mitre.org/top25/
- CWE 개별 정의 조회: https://cwe.mitre.org/data/definitions/{CWE번호}.html
