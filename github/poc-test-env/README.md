# PoC 재현 테스트 표준 환경

SCA로 추출한 CVE의 PoC를 격리된 환경에서 안전하게 재현·검증하기 위한 표준 템플릿 세트입니다.
CVE 하나마다 이 구조를 반복 생성해서, 재현 결과를 근거로 VEX 판단까지 연결하는 걸 목표로 합니다.

## 구조

```
poc-test-env/
├── scaffold_poc_env.py          # CVE ID를 넣으면 poc/{CVE-ID}/ 를 자동 생성하는 스크립트
├── templates/
│   ├── java/Dockerfile.template
│   ├── python/Dockerfile.template
│   ├── node/Dockerfile.template
│   ├── docker-compose.template.yml   # 격리 네트워크(internal: true) 구성
│   ├── run.sh.template               # 표준 실행 스크립트
│   └── RESULT_NOTES.template.md      # 검증 결과 + VEX 판단 기록 양식
└── poc/                          # CVE별 생성 결과가 여기 쌓임 (scaffold 실행 시 자동 생성)
    └── {CVE-ID}/
        ├── Dockerfile
        ├── docker-compose.yml
        ├── run.sh
        ├── RESULT_NOTES.md
        ├── src/app/               # PoC 앱 코드를 여기 넣음
        └── poc-scripts/           # 공격 스크립트를 여기 넣음
```

## 사용법

### 1) 새 CVE 테스트 환경 생성
```bash
python3 scaffold_poc_env.py CVE-2021-44228 java \
    --package "org.apache.logging.log4j:log4j-core" \
    --version "2.14.1" \
    --jdk 8
```
언어는 `java` / `python` / `node` 중 선택. Python은 `--python-version`, Node는 `--node-version` 옵션 사용.

### 2) PoC 코드 배치 (사람이 직접, 반드시 검토 후)
- `poc/{CVE-ID}/src/app/` — 취약한 애플리케이션 코드 (PoC 저장소의 샘플 앱을 그대로 쓰는 걸 권장)
- `poc/{CVE-ID}/poc-scripts/` — 공격 트리거 스크립트

⚠️ **여기서 코드를 그대로 clone해서 넣기 전에 반드시 내용을 읽고 검토하세요.** 공개 PoC 저장소에는 품질이 낮거나 의도치 않은 동작을 하는 코드가 섞여 있을 수 있습니다.

### 3) 격리 환경에서 실행
```bash
cd poc/CVE-2021-44228
./run.sh CVE-2021-44228
```
- 네트워크는 `internal: true`로 구성되어 외부 인터넷 접근이 원천 차단됩니다.
- attacker 컨테이너에 접속해서 수동으로 PoC 스크립트를 실행합니다:
  ```bash
  docker compose exec attacker bash
  ```

### 4) 결과 기록
`RESULT_NOTES.md`에 재현 여부, reachability 판단, VEX 상태(잠정)까지 기록합니다. 이 문서가 최종 VEX 산출의 근거 자료가 됩니다.

### 5) 정리
```bash
docker compose down -v
```

## 주의사항
- 이 템플릿은 **기본값이 "완전 네트워크 격리"**입니다. Blind SSRF나 OOB(Out-of-Band) 콜백을 검증해야 하는 특수 케이스는 `docker-compose.yml`의 네트워크 설정을 별도로 검토한 후 예외적으로만 변경하세요.
- `attacker` 이미지는 기본적으로 `kalilinux/kali-rolling`으로 되어 있으니, 필요한 도구에 맞게 교체하세요 (curl만 필요하면 훨씬 가벼운 이미지로 바꿔도 됩니다).
- Java 템플릿은 Maven 기준입니다. Gradle 프로젝트는 `Dockerfile`의 빌드 블록을 직접 수정하세요.
