## 분석 대상

- 키워드: modsecurity
- 분석한 소스 파일: 0
- 비교한 취약점 근거: 20

## 예측 요약

설정한 기준을 넘는 유사 취약 코드 후보를 찾지 못했습니다.

## 유사도 기반 취약 후보

후보 없음

## 근거 CVE

| CVE | 심각도 | 점수 | 설명 |
| --- | --- | ---: | --- |
| CVE-2018-16384 | HIGH | 7.5 | A SQL injection bypass (aka PL1 bypass) exists in OWASP ModSecurity Core Rule Set (owasp-modsecurity-crs) through v3.1.0-rc3 via {`a`b} where a is a special function name (such as "if") and b is the SQL statement to be executed. |
| CVE-2019-11388 | MEDIUM | 5.3 | An issue was discovered in OWASP ModSecurity Core Rule Set (CRS) through 3.1.0. /rules/REQUEST-932-APPLICATION-ATTACK-RCE.conf allows remote attackers to cause a denial of service (ReDOS) by entering a specially crafted string with nested repetition operators. NOTE: the software maintainer disputes that this is a vulnerability because the issue cannot be exploited via ModSecurity |
| CVE-2019-11389 | MEDIUM | 5.3 | An issue was discovered in OWASP ModSecurity Core Rule Set (CRS) through 3.1.0. /rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf allows remote attackers to cause a denial of service (ReDOS) by entering a specially crafted string with next# at the beginning and nested repetition operators. NOTE: the software maintainer disputes that this is a vulnerability because the issue cannot be exploited via ModSecurity |
| CVE-2019-11390 | MEDIUM | 5.3 | An issue was discovered in OWASP ModSecurity Core Rule Set (CRS) through 3.1.0. /rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf allows remote attackers to cause a denial of service (ReDOS) by entering a specially crafted string with set_error_handler# at the beginning and nested repetition operators. NOTE: the software maintainer disputes that this is a vulnerability because the issue cannot be exploited via ModSecurity |
| CVE-2019-11391 | MEDIUM | 5.3 | An issue was discovered in OWASP ModSecurity Core Rule Set (CRS) through 3.1.0. /rules/REQUEST-933-APPLICATION-ATTACK-PHP.conf allows remote attackers to cause a denial of service (ReDOS) by entering a specially crafted string with $a# at the beginning and nested repetition operators. NOTE: the software maintainer disputes that this is a vulnerability because the issue cannot be exploited via ModSecurity |
| CVE-2013-5705 | UNKNOWN | 5.0 | apache2/modsecurity.c in ModSecurity before 2.7.6 allows remote attackers to bypass rules by using chunked transfer coding with a capitalized Chunked value in the Transfer-Encoding HTTP header. |
| CVE-2016-10817 | CRITICAL | 9.8 | cPanel before 57.9999.54 allows SQL Injection via the ModSecurity TailWatch log file (SEC-123). |
| CVE-2002-1135 | UNKNOWN | 7.5 | modsecurity.php 1.10 and earlier, in phpWebSite 0.8.2 and earlier, allows remote attackers to execute arbitrary PHP source code via an inc_prefix parameter that points to the malicious code. |
| CVE-2004-1765 | UNKNOWN | 7.5 | Off-by-one buffer overflow in ModSecurity (mod_security) 1.7.4 for Apache 2.x, when SecFilterScanPost is enabled, allows remote attackers to execute arbitrary code via crafted POST requests. |
| CVE-2013-1915 | UNKNOWN | 7.5 | ModSecurity before 2.7.3 allows remote attackers to read arbitrary files, send HTTP requests to intranet servers, or cause a denial of service (CPU and memory consumption) via an XML external entity declaration in conjunction with an entity reference, aka an XML External Entity (XXE) vulnerability. |

## 해석 방법

이 결과는 확정 진단이 아니라, 이미 제보된 취약 코드 또는 CVE 설명과의 유사도를 이용한 우선순위 후보입니다. 상위 후보부터 입력 검증, 경계값 검사, 메모리 크기 계산, 인증/세션 처리, 인코딩/디코딩 흐름을 수동 검토하세요.