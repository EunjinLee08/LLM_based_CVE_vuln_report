# CVE Similarity Vulnerability Predictor

이 프로젝트는 CVE/NVD에 이미 제보된 취약점 설명과, 선택적으로 별도 보관한 취약 코드 샘플을 근거로 대상 소스 코드의 유사 취약 후보를 예측합니다.

단순히 CVE 키워드를 검색해 리포트를 생성하는 방식이 아니라, 수집한 CVE 설명과 취약 코드 샘플을 `VulnerabilityPattern`으로 변환한 뒤 대상 소스 코드와의 유사도를 계산합니다. 이후 유사도 상위 후보를 LLM이 재검토하여 실제 취약 가능성, 오탐 가능성, 확인 방법, 권장 조치를 포함한 Markdown 리포트를 생성합니다.

## 주요 기능

* NVD API 기반 CVE 설명 수집
* GitHub file/blob/tree/repository URL 기반 소스 코드 수집
* 로컬 소스 디렉터리 분석
* 과거 취약 코드 샘플 기반 코드 유사도 비교
* CVE 설명 기반 fallback 유사도 비교
* LLM 기반 상위 후보 재검토
* Markdown 형식의 similarity report 생성

## 프로젝트 구조

```text
project/
├── src/
│   ├── collectors/   # NVD와 GitHub 웹 URL에서 분석 근거 수집
│   ├── parser/       # NVD 응답을 공통 CVE 모델로 정규화
│   ├── retrieval/    # CVE/취약 코드 샘플과 대상 코드의 유사도 계산
│   ├── llm/          # LLM 재판단 및 Markdown 리포트 생성
│   ├── validation/   # 입력값과 결과 검증
│   ├── config.py     # 환경 변수 기반 실행 설정
│   └── main.py       # CLI 진입점
└── reports/          # 생성된 분석 리포트 저장
```

## 실행 준비

```powershell
cd project
pip install -r requirements.txt
```

NVD API 키가 있다면 환경 변수로 설정할 수 있습니다. 키가 없어도 실행은 가능하지만, NVD API 사용량 제한에 영향을 받을 수 있습니다.

```powershell
$env:NVD_API_KEY="your-nvd-api-key"
```

현재 similarity 분석 리포트 생성 과정에서는 LLM 재판단을 수행하므로 `MINDLOGIC_API_KEY`가 필요합니다.

```powershell
$env:MINDLOGIC_API_KEY="your-mindlogic-api-key"
$env:MINDLOGIC_BASE_URL="https://factchat-cloud.mindlogic.ai/v1/gateway"
$env:MINDLOGIC_MODEL="gpt-5.4"
```

선택적으로 결과 저장 위치와 기본 CVE 수집 개수를 환경 변수로 조정할 수 있습니다.

```powershell
$env:REPORT_OUTPUT_DIR="reports"
$env:MAX_CVE_RESULTS="5"
$env:LLM_MAX_FINDINGS="5"
```

## 로컬 소스 디렉터리 분석

`--source-dir`에는 리포트 파일이 아니라 실제 `.c`, `.h`, `.cpp`, `.py`, `.js`, `.ts`, `.java`, `.php`, `.go`, `.rs`, `.rb` 같은 소스 파일이 들어 있어야 합니다.

```powershell
cd project
python -m src.main "openssl" --source-dir path/to/source --limit 20
```

분석 흐름은 다음과 같습니다.

1. `"openssl"` 키워드로 NVD에서 관련 CVE를 수집합니다.
2. CVE 설명을 취약점 패턴으로 변환합니다.
3. `path/to/source` 내부의 소스 코드를 snippet 단위로 나눕니다.
4. CVE 패턴과 대상 코드 snippet의 유사도를 계산합니다.
5. 상위 후보를 LLM이 재검토합니다.
6. `reports/` 디렉터리에 Markdown 리포트를 생성합니다.

## 이전 제보 취약 코드 샘플과 비교

`--vuln-code-dir`에는 과거에 취약점으로 제보된 코드 파일을 넣습니다. 이 옵션을 주면 CVE 설명뿐 아니라 취약 코드 샘플과 대상 코드 사이의 코드 유사도도 함께 반영합니다.

```powershell
cd project
python -m src.main "modsecurity" --source-dir path/to/source --vuln-code-dir known_vulnerable_samples --limit 20
```

이 방식은 CVE 설명문만으로는 포착하기 어려운 코드 구조, 함수 호출 패턴, 조건문 형태, 입력 검증 누락 패턴을 함께 비교하기 위한 용도입니다.

## GitHub URL을 바로 분석

GitHub 파일, tree, repository URL을 넣으면 소스를 직접 클론하지 않고 유사도 분석 리포트를 생성할 수 있습니다.

```powershell
cd project
python -m src.main "openssl" --github-url "https://github.com/owner/repo/blob/main/src/app.c"
```

GitHub tree URL을 넣으면 해당 경로 아래의 소스 파일을 가져와 분석합니다.

```powershell
cd project
python -m src.main "openssl" --github-url "https://github.com/owner/repo/tree/main/src" --github-max-files 20
```

키워드를 생략하면 GitHub 저장소 이름을 NVD 검색 키워드로 사용합니다.

```powershell
cd project
python -m src.main --github-url "https://github.com/owasp-modsecurity/ModSecurity/tree/v2.9.11/apache2" --limit 20
```

## GitHub 소스 파일만 저장

GitHub URL에서 가져온 소스 파일을 분석하지 않고 저장만 하려면 `--save-sources`를 사용합니다.

```powershell
cd project
python -m src.main "openssl" --github-url "https://github.com/owner/repo/tree/main/src" --save-sources
```

저장된 파일은 기본적으로 `reports/` 디렉터리에 `source__` 접두사가 붙은 이름으로 생성됩니다.

## 튜닝 옵션

* `--limit`: NVD에서 가져올 CVE 개수
* `--source-dir`: 분석할 로컬 소스 코드 디렉터리
* `--vuln-code-dir`: 이전 제보 취약 코드 샘플 디렉터리
* `--threshold`: 후보로 보고할 최소 유사도. 기본값은 `0.18`
* `--max-findings`: 리포트에 포함할 최대 후보 수. 기본값은 `20`
* `--github-url`: 분석할 GitHub file/tree/repository URL
* `--github-max-files`: GitHub repository/tree URL에서 가져올 최대 파일 수. 기본값은 `20`
* `--save-sources`: GitHub URL에서 가져온 소스 파일을 분석하지 않고 저장만 수행
* `--show-prompt`: 일반 CVE 리포트 생성 시 LLM prompt evidence block 출력

## 환경 변수

| 환경 변수                | 설명                                | 기본값                                              |
| -------------------- | --------------------------------- | ------------------------------------------------ |
| `NVD_API_KEY`        | NVD API 키                         | 없음                                               |
| `MINDLOGIC_API_KEY`  | LLM 재판단에 사용할 API 키                | 없음                                               |
| `MINDLOGIC_BASE_URL` | OpenAI-compatible LLM gateway URL | `https://factchat-cloud.mindlogic.ai/v1/gateway` |
| `MINDLOGIC_MODEL`    | LLM 재판단에 사용할 모델                   | `gpt-5.4`                                        |
| `REPORT_OUTPUT_DIR`  | 리포트 저장 디렉터리                       | `project/reports`                                |
| `MAX_CVE_RESULTS`    | 기본 CVE 수집 개수                      | `5`                                              |
| `LLM_MAX_FINDINGS`   | LLM에 보낼 상위 후보 수                   | `5`                                              |

## 결과 리포트

분석이 끝나면 다음과 같은 파일이 생성됩니다.

```text
project/reports/YYYYMMDD_HHMMSS_<keyword>_similarity.md
```

리포트에는 다음 내용이 포함됩니다.

* 분석 키워드
* 수집된 CVE 근거
* 분석한 소스 파일 수
* 생성된 취약점 패턴 수
* 유사 취약 후보 목록
* 유사도 점수
* 매칭 근거
* LLM 재판단 결과
* 오탐 가능성
* 확인 방법
* 권장 수정 방향

## 주의사항

이 도구는 알려진 CVE 설명과 취약 코드 샘플을 기반으로 유사 취약 후보를 찾는 보조 분석 도구입니다. 결과는 실제 취약점의 확정 판정이 아니며, 최종 판단에는 별도의 코드 리뷰, 테스트, 패치 이력 확인이 필요합니다.

또한 LLM 재판단 결과는 상위 후보의 위험성을 설명하고 검토 방향을 제시하기 위한 용도입니다. 공격 재현 절차나 weaponized payload 생성을 목적으로 하지 않습니다.