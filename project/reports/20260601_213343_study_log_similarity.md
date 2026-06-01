## 분석 대상

- 키워드: study log
- 분석한 소스 파일: 1
- 비교한 취약점 근거: 5

## 예측 요약

설정한 기준을 넘는 유사 취약 코드 후보를 찾지 못했습니다.

## 유사도 기반 취약 후보

후보 없음

## 근거 CVE

| CVE | 심각도 | 점수 | 설명 |
| --- | --- | ---: | --- |
| CVE-2021-42330 | HIGH | 8.8 | The “Teacher Edit” function of ShinHer StudyOnline System does not perform authority control. After logging in with user’s privilege, remote attackers can access and edit other users’ credential and personal information by crafting URL parameters. |
| CVE-2021-42329 | MEDIUM | 5.4 | The “List_Add” function of message board of ShinHer StudyOnline System does not filter special characters in the title parameter. After logging in with user’s privilege, remote attackers can inject JavaScript and execute stored XSS attacks. |
| CVE-2021-42331 | MEDIUM | 5.4 | The “Study Edit” function of ShinHer StudyOnline System does not perform permission control. After logging in with user’s privilege, remote attackers can access and edit other users’ tutorial schedule by crafting URL parameters. |
| CVE-2026-28675 | MEDIUM | 5.3 | OpenSift is an AI study tool that sifts through large datasets using semantic search and generative AI. Prior to version 1.6.3-alpha, some endpoints returned raw exception strings to clients. Additionally, login token material was exposed in UI/rendered responses and token rotation output. This issue has been patched in version 1.6.3-alpha. |
| CVE-2021-42332 | MEDIUM | 4.3 | The “List View” function of ShinHer StudyOnline System is not under authority control. After logging in with user’s privilege, remote attackers can access the content of other users’ message boards by crafting URL parameters. |

## 해석 방법

이 결과는 확정 진단이 아니라, 이미 제보된 취약 코드 또는 CVE 설명과의 유사도를 이용한 우선순위 후보입니다. 상위 후보부터 입력 검증, 경계값 검사, 메모리 크기 계산, 인증/세션 처리, 인코딩/디코딩 흐름을 수동 검토하세요.