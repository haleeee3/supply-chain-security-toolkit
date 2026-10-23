# {CVE-ID} 재현 검증 노트

## 기본 정보
- CVE ID:
- CWE 유형: (CWE Top 25 참고 문서에서 확인)
- 대상 컴포넌트/버전:
- PoC 출처: (nomi-sec / GitHub 검색 / Exploit-DB 등, URL 명시)

## 사전 검토
- [ ] PoC 코드를 직접 읽고 검토함
- [ ] 네트워크 요청 대상 확인함 (외부 콜백 여부: 있음 / 없음)
- [ ] 파일 쓰기/삭제 동작 확인함
- [ ] 격리 환경(네트워크 차단) 구성 완료

## 실행 조건
- 사용 이미지/버전:
- 실행 커맨드:
- 실행 일시:

## 결과
- 재현 여부: [ ] 성공 [ ] 실패 [ ] 조건부(설명 필요)
- 트리거 조건 (재현 성공 시): 어떤 입력/설정에서 트리거되는지 구체적으로
- 로그/스크린샷 경로:

## Reachability 판단
- 실제 운영 코드가 이 취약 경로를 호출하는가? [ ] 예 [ ] 아니오 [ ] 확인 불가
- 근거:

## VEX 판단 (잠정)
- 상태: [ ] not_affected [ ] affected [ ] fixed [ ] under_investigation
- (not_affected인 경우) justification 코드:
  - [ ] component_not_present
  - [ ] vulnerable_code_not_present
  - [ ] vulnerable_code_not_in_execute_path
  - [ ] vulnerable_code_cannot_be_controlled_by_adversary
  - [ ] inline_mitigations_already_exist
- impact_statement (판단 근거 서술):

## 후속 조치
- [ ] 개발팀에 공유 필요
- [ ] 패치 버전 확인 필요
- [ ] 추가 조사 필요 (사유: )
