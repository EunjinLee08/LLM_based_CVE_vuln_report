## 분석 대상

- 키워드: modsecurity
- 분석한 소스 파일: 18
- 비교한 취약점 근거: 10

## 예측 요약

총 10개의 후보를 찾았습니다. 높음 0개, 중간 1개, 낮음 9개입니다.

## 유사도 기반 취약 후보

| 위험도 | 유사도 | 위치 | 유사 근거 | 매칭 용어 |
| --- | ---: | --- | --- | --- |
| 중간 | 0.32 | `source__apache2__apache2_config.c:3062-3082` | CVE-2013-1915 | entity, external, mod, security, xml |
| 낮음 | 0.29 | `source__apache2__apache2_io.c:371-427` | CVE-2013-2765 | null, body, content, for, header, request, type |
| 낮음 | 0.28 | `source__apache2__apache2_config.c:2612-2680` | CVE-2013-2765 | null, mod, remote, security, server |
| 낮음 | 0.26 | `source__apache2__apache2_config.c:2612-2680` | CVE-2008-5676 | mod, remote, sec, security, server |
| 낮음 | 0.26 | `source__apache2__apache2_config.c:2612-2680` | CVE-2007-1359 | mod, remote, rules, security |
| 낮음 | 0.26 | `source__apache2__mod_security2.c:3-153` | CVE-2013-2765 | null, pointer, apache, for, http, mod, module, remote, request, security, server |
| 낮음 | 0.25 | `source__apache2__apache2_config.c:3599-3698` | CVE-2008-5676 | cache, enabled, for, mod, sec, security, transformations |
| 낮음 | 0.25 | `source__apache2__apache2_config.c:2612-2680` | CVE-2004-1765 | mod, one, remote, sec, security |
| 낮음 | 0.24 | `source__apache2__apache2_config.c:2864-2869` | CVE-2013-2765 | null, mod, security, server |
| 낮음 | 0.24 | `source__apache2__apache2_config.c:2612-2680` | CVE-2009-1902 | null, mod, remote, security |

## 근거 CVE

| CVE | 심각도 | 점수 | 설명 |
| --- | --- | ---: | --- |
| CVE-2002-1135 | UNKNOWN | 7.5 | modsecurity.php 1.10 and earlier, in phpWebSite 0.8.2 and earlier, allows remote attackers to execute arbitrary PHP source code via an inc_prefix parameter that points to the malicious code. |
| CVE-2004-1765 | UNKNOWN | 7.5 | Off-by-one buffer overflow in ModSecurity (mod_security) 1.7.4 for Apache 2.x, when SecFilterScanPost is enabled, allows remote attackers to execute arbitrary code via crafted POST requests. |
| CVE-2013-1915 | UNKNOWN | 7.5 | ModSecurity before 2.7.3 allows remote attackers to read arbitrary files, send HTTP requests to intranet servers, or cause a denial of service (CPU and memory consumption) via an XML external entity declaration in conjunction with an entity reference, aka an XML External Entity (XXE) vulnerability. |
| CVE-2007-1359 | UNKNOWN | 6.8 | Interpretation conflict in ModSecurity (mod_security) 2.1.0 and earlier allows remote attackers to bypass request rules via application/x-www-form-urlencoded POST data that contains an ASCIIZ (0x00) byte, which mod_security treats as a terminator even though it is still processed as normal data by some HTTP parsers including PHP 5.2.0, and possibly parsers in Perl, and Python. |
| CVE-2008-5676 | UNKNOWN | 5.0 | Multiple unspecified vulnerabilities in the ModSecurity (aka mod_security) module 2.5.0 through 2.5.5 for the Apache HTTP Server, when SecCacheTransformations is enabled, allow remote attackers to cause a denial of service (daemon crash) or bypass the product's functionality via unknown vectors related to "transformation caching." |
| CVE-2009-1902 | UNKNOWN | 5.0 | The multipart processor in ModSecurity before 2.5.9 allows remote attackers to cause a denial of service (crash) via a multipart form datapost request with a missing part header name, which triggers a NULL pointer dereference. |
| CVE-2013-2765 | UNKNOWN | 5.0 | The ModSecurity module before 2.7.4 for the Apache HTTP Server allows remote attackers to cause a denial of service (NULL pointer dereference, process crash, and disk consumption) via a POST request with a large body and a crafted Content-Type header. |
| CVE-2009-1903 | UNKNOWN | 4.3 | The PDF XSS protection feature in ModSecurity before 2.5.8 allows remote attackers to cause a denial of service (Apache httpd crash) via a request for a PDF file that does not use the GET method. |
| CVE-2009-5031 | UNKNOWN | 4.3 | ModSecurity before 2.5.11 treats request parameter values containing single quotes as files, which allows remote attackers to bypass filtering rules and perform other attacks such as cross-site scripting (XSS) attacks via a single quote in a request parameter in the Content-Disposition field of a request with a multipart/form-data Content-Type header. |
| CVE-2012-2751 | UNKNOWN | 4.3 | ModSecurity before 2.6.6, when used with PHP, does not properly handle single quotes not at the beginning of a request parameter value in the Content-Disposition field of a request with a multipart/form-data Content-Type header, which allows remote attackers to bypass filtering rules and perform other attacks such as cross-site scripting (XSS) attacks.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2009-5031. |

## 해석 방법

이 결과는 확정 진단이 아니라, 이미 제보된 취약 코드 또는 CVE 설명과의 유사도를 이용한 우선순위 후보입니다. 상위 후보부터 입력 검증, 경계값 검사, 메모리 크기 계산, 인증/세션 처리, 인코딩/디코딩 흐름을 수동 검토하세요.