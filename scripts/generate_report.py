#!/usr/bin/env python3
"""
Supply Chain Security Report Generator
CVE 스캔 결과 + EPSS + NVD 정보를 종합해서 보고서 생성
"""

import json
import urllib.request
import sys
from datetime import datetime

def fetch_epss(cve_ids):
    """EPSS 점수 조회"""
    if not cve_ids:
        return {}
    
    query = ','.join(cve_ids[:100])
    url = f"https://api.first.org/data/v1/epss?cve={query}"
    
    try:
        with urllib.request.urlopen(url) as res:
            data = json.load(res)
        return {
            item['cve']: {
                'epss': float(item['epss']),
                'percentile': float(item['percentile'])
            }
            for item in data.get('data', [])
        }
    except Exception as e:
        print(f"⚠️ EPSS 조회 실패: {e}")
        return {}

def fetch_nvd(cve_id):
    """NVD에서 CVE 상세 정보 조회"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as res:
            data = json.load(res)
        
        items = data.get('vulnerabilities', [])
        if not items:
            return {}
        
        cve_data = items[0].get('cve', {})
        
        # 설명
        descriptions = cve_data.get('descriptions', [])
        desc = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')
        
        # CVSS
        metrics = cve_data.get('metrics', {})
        cvss_data = metrics.get('cvssMetricV31', metrics.get('cvssMetricV30', []))
        cvss_score = ''
        cvss_vector = ''
        if cvss_data:
            cvss_score = cvss_data[0].get('cvssData', {}).get('baseScore', '')
            cvss_vector = cvss_data[0].get('cvssData', {}).get('vectorString', '')
        
        # CWE
        weaknesses = cve_data.get('weaknesses', [])
        cwes = []
        for w in weaknesses:
            for d in w.get('description', []):
                if d.get('value', '').startswith('CWE-'):
                    cwes.append(d['value'])
        
        return {
            'description': desc[:300] + '...' if len(desc) > 300 else desc,
            'cvss_score': cvss_score,
            'cvss_vector': cvss_vector,
            'cwe': ', '.join(cwes) if cwes else 'N/A'
        }
    
    except Exception as e:
        print(f"⚠️ NVD 조회 실패 ({cve_id}): {e}")
        return {}

def determine_vex(severity, epss_score):
    """간단한 VEX 판단"""
    if severity in ['Critical', 'High'] and epss_score > 0.5:
        return 'affected', '즉시 패치 필요'
    elif severity in ['Critical', 'High'] and epss_score > 0.1:
        return 'affected', '패치 권고'
    elif severity in ['Medium']:
        return 'under_investigation', '추가 검토 필요'
    else:
        return 'not_affected', '낮은 위험도'

def generate_report(cve_results_path='cve-results.json'):
    """보고서 생성 메인 함수"""
    
    print(f"\n{'='*60}")
    print(f"  Supply Chain Security Report")
    print(f"  생성일시: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}\n")
    
    # CVE 결과 로드
    try:
        with open(cve_results_path) as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"❌ {cve_results_path} 파일을 찾을 수 없어요.")
        print("먼저 Grype로 스캔을 실행하세요:")
        print("  grype . --by-cve -o json > cve-results.json")
        sys.exit(1)
    
    matches = data.get('matches', [])
    
    # CVE ID 목록 추출
    cve_map = {}
    for m in matches:
        cve_id = m['vulnerability']['id']
        if not cve_id.startswith('CVE-'):
            continue
        
        severity = m['vulnerability'].get('severity', 'Unknown')
        pkg = m.get('artifact', {})
        pkg_name = pkg.get('name', 'Unknown')
        pkg_version = pkg.get('version', 'Unknown')
        
        # 수정 버전
        fix_versions = m['vulnerability'].get('fix', {}).get('versions', [])
        fix_version = fix_versions[0] if fix_versions else '패치 없음'
        
        if cve_id not in cve_map:
            cve_map[cve_id] = {
                'severity': severity,
                'packages': [],
                'fix_version': fix_version
            }
        cve_map[cve_id]['packages'].append(f"{pkg_name}=={pkg_version}")
    
    if not cve_map:
        print("✅ CVE 발견 없음!")
        return
    
    print(f"📊 총 발견된 CVE: {len(cve_map)}개\n")
    
    # EPSS 일괄 조회
    print("🔍 EPSS 점수 조회 중...")
    epss_data = fetch_epss(list(cve_map.keys()))
    
    # 결과 정리
    report = []
    for cve_id, info in cve_map.items():
        epss_info = epss_data.get(cve_id, {})
        epss_score = epss_info.get('epss', 0)
        epss_pct = epss_info.get('percentile', 0)
        
        vex_status, action = determine_vex(info['severity'], epss_score)
        
        report.append({
            'cve': cve_id,
            'severity': info['severity'],
            'epss': epss_score,
            'epss_percentile': epss_pct,
            'packages': info['packages'],
            'fix_version': info['fix_version'],
            'vex_status': vex_status,
            'action': action
        })
    
    # 심각도 순 정렬
    severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Unknown': 4}
    report.sort(key=lambda x: (severity_order.get(x['severity'], 4), -x['epss']))
    
    # 출력
    print(f"\n{'─'*60}")
    print(f"{'즉시 조치 필요':^60}")
    print(f"{'─'*60}")
    
    urgent = [r for r in report if r['vex_status'] == 'affected']
    if urgent:
        for item in urgent:
            print(f"\n🚨 {item['cve']}")
            print(f"   심각도    : {item['severity']}")
            print(f"   EPSS     : {item['epss']*100:.2f}% (상위 {item['epss_percentile']*100:.1f}%)")
            print(f"   영향 패키지: {', '.join(set(item['packages']))}")
            print(f"   수정 버전  : {item['fix_version']}")
            print(f"   VEX      : {item['vex_status']}")
            print(f"   조치      : {item['action']}")
    else:
        print("  없음 ✅")
    
    print(f"\n{'─'*60}")
    print(f"{'추가 검토 필요':^60}")
    print(f"{'─'*60}")
    
    investigate = [r for r in report if r['vex_status'] == 'under_investigation']
    if investigate:
        for item in investigate:
            print(f"\n⚠️  {item['cve']}")
            print(f"   심각도    : {item['severity']}")
            print(f"   EPSS     : {item['epss']*100:.2f}%")
            print(f"   영향 패키지: {', '.join(set(item['packages']))}")
            print(f"   조치      : {item['action']}")
    else:
        print("  없음 ✅")
    
    # JSON 보고서 저장
    output = {
        'generated_at': datetime.now().isoformat(),
        'total_cve': len(report),
        'urgent': len(urgent),
        'investigate': len(investigate),
        'details': report
    }
    
    with open('security-report.json', 'w', encoding='utf-8') as f:
        json.dump(output, f, ensure_ascii=False, indent=2)
    
    print(f"\n{'='*60}")
    print(f"✅ 보고서 저장 완료: security-report.json")
    print(f"   즉시 조치 필요: {len(urgent)}건")
    print(f"   추가 검토 필요: {len(investigate)}건")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else 'cve-results.json'
    generate_report(path)