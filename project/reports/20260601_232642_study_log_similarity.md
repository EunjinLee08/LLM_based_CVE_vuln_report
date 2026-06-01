## 분석 대상

- 키워드: study log
- 분석한 소스 파일: 1
- 비교한 취약점 근거: 11

## 예측 요약

설정한 기준을 넘는 유사 취약 코드 후보를 찾지 못했습니다.

## Static C Pattern Evidence

| Family | CWE | File | Line | Sink | Confidence | Reason |
| --- | --- | --- | ---: | --- | ---: | --- |
| command_injection | CWE-78 | projects/30th_hacking_camp_ctf/prob/chall.c | 22 | system | 0.50 | command execution sink is used |
| format_string | CWE-134 | projects/30th_hacking_camp_ctf/prob/chall.c | 36 | printf | 0.85 | format string argument appears externally influenced and is not a string literal |

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
| CVE-2018-1000042 | CRITICAL | 9.8 | Security Onion Solutions Squert version 1.3.0 through 1.6.7 contains a CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) vulnerability in .inc/callback.php that can result in execution of OS Commands. This attack appear to be exploitable via Web request to .inc/callback.php with the payload in the data or obj parameters, used in autocat(). This vulnerability appears to have been fixed in 1.7.0. |
| CVE-2018-1000043 | CRITICAL | 9.8 | Security Onion Solutions Squert version 1.0.1 through 1.6.7 contains a CWE-78: Improper Neutralization of Special Elements used in an OS Command (OS Command Injection) vulnerability in .inc/callback.php that can result in execution of OS Commands. This attack appear to be exploitable via Web request to .inc/callback.php with the payload in the txdata parameter, used in tx()/transcript(), or the catdata parameter, used in cat(). This vulnerability appears to have been fixed in 1.7.0. |
| CVE-2018-1000666 | CRITICAL | 9.8 | GIG Technology NV JumpScale Portal 7 version before commit 15443122ed2b1cbfd7bdefc048bf106f075becdb contains a CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') vulnerability in method: notifySpaceModification; that can result in Improper validation of parameters results in command execution. This attack appear to be exploitable via Network connectivity, required minimal auth privileges (everyone can register an account). This vulnerability appears to have been fixed in After commit 15443122ed2b1cbfd7bdefc048bf106f075becdb. |
| CVE-2019-1010200 | CRITICAL | 9.8 | Voice Builder Prior to commit c145d4604df67e6fc625992412eef0bf9a85e26b and f6660e6d8f0d1d931359d591dbdec580fef36d36 is affected by: CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'). The impact is: Remote code execution with the same privileges as the servers. The component is: Two web servers in the projects expose three vulnerable endpoints that can be accessed remotely. The endpoints are defined at: - /tts: https://github.com/google/voice-builder/blob/3a449a3e8d5100ff323161c89b897f6d5ccdb6f9/merlin_model_server/api.js#L34 - /alignment: https://github.com/google/voice-builder/blob/3a449a3e8d5100ff323161c89b897f6d5ccdb6f9/festival_model_server/api.js#L28 - /tts: https://github.com/google/voice-builder/blob/3a449a3e8d5100ff323161c89b897f6d5ccdb6f9/festival_model_server/api.js#L65. The attack vector is: Attacker sends a GET request to the vulnerable endpoint with a specially formatted query parameter. The fixed version is: After commit f6660e6d8f0d1d931359d591dbdec580fef36d36. |
| CVE-2020-7350 | MEDIUM | 6.1 | Rapid7 Metasploit Framework versions before 5.0.85 suffers from an instance of CWE-78: OS Command Injection, wherein the libnotify plugin accepts untrusted user-supplied data via a remote computer's hostname or service name. An attacker can create a specially-crafted hostname or service name to be imported by Metasploit from a variety of sources and trigger a command injection on the operator's terminal. Note, only the Metasploit Framework and products that expose the plugin system is susceptible to this issue -- notably, this does not include Rapid7 Metasploit Pro. Also note, this vulnerability cannot be triggered through a normal scan operation -- the attacker would have to supply a file that is processed with the db_import command. |

## 해석 방법

이 결과는 확정 진단이 아니라, 이미 제보된 취약 코드 또는 CVE 설명과의 유사도를 이용한 우선순위 후보입니다. 상위 후보부터 입력 검증, 경계값 검사, 메모리 크기 계산, 인증/세션 처리, 인코딩/디코딩 흐름을 수동 검토하세요.