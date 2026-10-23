# VEX (Vulnerability Exploitability eXchange) 핵심 정리 — 컨설팅 참고용

## 1. VEX가 왜 필요한가

SBOM(Software Bill of Materials)은 "이 소프트웨어에 어떤 컴포넌트가 들어있는지"만 알려줍니다. 여기에 CVE를 매칭하면 "이 컴포넌트에 이런 취약점이 등록되어 있다"까지는 알 수 있지만, **"우리 제품에서 실제로 악용 가능한지"는 알 수 없습니다.**

- SBOM + CVE 매칭 = 잠재적 위험 목록 (노이즈 많음)
- **SBOM + CVE + VEX = 실제 조치가 필요한 위험 목록** (노이즈 제거)

즉 VEX는 "이 CVE가 우리 제품에 실제로 영향을 미치는가?"에 대한 **공급자(vendor)의 공식 판단**을 기계가 읽을 수 있는 형태로 문서화한 것입니다. 컨설팅 업무에서 VEX 도출은 결국 이 판단을 "근거를 가지고" 내리는 작업입니다.

관련 표준: CSAF(OASIS), CycloneDX VEX, OpenVEX — 이 중 OpenVEX가 상태값 정의가 가장 간결해서 개념 이해에 적합합니다.

---

## 2. 4가지 상태값 (Status)

| 상태 | 의미 | 실무적 의미 |
|---|---|---|
| `not_affected` | 이 CVE는 우리 제품에서 악용 불가능함 | **조치 불필요** — 근거(justification) 필수 |
| `affected` | 이 CVE는 실제로 악용 가능함 | **조치 필요** — 대응 계획(action_statement) 명시 |
| `fixed` | 과거엔 영향받았으나 이미 패치 완료 | 조치 완료, 어느 버전부터 수정됐는지 명시 |
| `under_investigation` | 아직 조사 중 (판단 보류) | 잠정 상태 — 후속 VEX 문서로 업데이트 예정임을 알림 |

**컨설팅 관점에서 가장 중요한 상태는 `not_affected`입니다.** 이걸 제대로 판단해야 고객이 "당장 패치해야 할 것"과 "무시해도 되는 것"을 구분할 수 있기 때문입니다. 그리고 이 판단에는 **반드시 근거(justification)가 있어야** 합니다 — "그냥 안전할 것 같다"가 아니라 아래 5가지 근거 코드 중 하나로 명확히 설명해야 합니다.

---

## 3. `not_affected`의 5가지 근거 코드 (Justification)

| 코드 | 의미 | 어떻게 확인하나 |
|---|---|---|
| `component_not_present` | 애초에 해당 컴포넌트가 제품에 포함 안 됨 | SCA가 이름만 보고 오탐한 경우 (버전 문자열 유사 등) |
| `vulnerable_code_not_present` | 컴포넌트는 있지만, 취약한 코드 자체가 빌드에 포함 안 됨 | 해당 라이브러리의 일부 모듈만 사용 / 조건부 컴파일로 제외된 경우 |
| `vulnerable_code_not_in_execute_path` | 취약한 코드는 있지만 실행 경로상 호출되지 않음 | **Reachability 분석**의 핵심 대상 — "우리 코드가 이 함수를 호출하는가?" |
| `vulnerable_code_cannot_be_controlled_by_adversary` | 취약 코드가 호출되긴 하지만, 공격자가 그 입력을 조작할 수 없음 | 예: 취약 함수가 사용자 입력이 아니라 내부 고정값만 받는 경우 |
| `inline_mitigations_already_exist` | 별도 패치나 WAF/설정 등으로 이미 완화 조치가 되어 있음 | 시큐어 코딩, 입력 검증 로직, 방화벽 규칙 등이 실제로 그 공격을 막는지 확인 필요 |

> **컨설팅 실무 팁**: 이 중 `vulnerable_code_not_in_execute_path`가 가장 자주 쓰이고, 동시에 가장 잘못 판단하기 쉬운 항목입니다. "우리는 이 라이브러리의 그 함수를 안 쓴다"는 개발자의 구두 확인만으로는 근거로 부족하고, 실제 코드에서 호출 관계(call graph)를 추적하거나 SCA 도구의 reachability 분석 기능으로 확인한 결과를 근거로 남겨야 감사(audit) 시 방어가 가능합니다.

---

## 4. VEX 문서 예시 (OpenVEX 형식, 개념 이해용)

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/CVE-2021-44228-billing-app",
  "author": "컨설팅사명 / 고객사명",
  "timestamp": "2026-09-27T00:00:00Z",
  "statements": [
    {
      "vulnerability": { "name": "CVE-2021-44228" },
      "products": [ { "@id": "pkg:maven/billing-app@1.4.0" } ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "billing-app은 log4j-core를 의존성으로 포함하지만, JNDI lookup을 트리거하는 로그 패턴(${jndi:...})을 절대 사용자 입력에서 받지 않으며, 해당 로그 포맷 문자열은 고정 문자열만 사용함. 정적 분석(코드리뷰 + grep) 및 call graph 분석으로 확인함."
    }
  ]
}
```

이 예시처럼 **`impact_statement`(또는 `action_statement`)에 판단 근거를 구체적으로 서술하는 것**이 컨설팅 산출물의 실질적인 핵심입니다. 상태값 하나만 던지면 고객도, 나중에 감사하는 사람도 신뢰할 수 없습니다.

---

## 5. 컨설팅 워크플로우에 대입하면

1. SCA로 CVE 목록 도출
2. 각 CVE의 CWE 유형 확인 (→ CWE Top 25 문서 참고)
3. **Reachability 분석**: 취약 코드가 실제로 호출되는지 확인 (도구 활용 또는 개발팀 협업)
   - 호출 안 됨 → `not_affected` + `vulnerable_code_not_in_execute_path`
   - 호출은 되지만 공격자가 입력 통제 불가 → `not_affected` + `vulnerable_code_cannot_be_controlled_by_adversary`
   - 호출되고 공격자가 입력도 통제 가능 → PoC로 실제 검증 필요
4. PoC 실행 검증 (격리 환경)
   - 재현 성공 → `affected` (패치 전) 또는 `fixed` (패치 후 재검증)
   - 재현 실패했지만 이유가 불명확 → `under_investigation`으로 임시 기록, 원인 추가 조사
5. 모든 판단에 근거를 남겨 VEX 문서로 산출 → 이게 최종 컨설팅 결과물

---

## 참고 자료
- OpenVEX 스펙: https://github.com/openvex/spec
- CycloneDX VEX 유스케이스: https://cyclonedx.org/use-cases/vulnerability-exploitability
- CISA/NTIA VEX 개요: https://www.cisa.gov/resources-tools/resources/minimum-requirements-vulnerability-exploitability-exchange-vex
