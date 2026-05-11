# CVE Similarity Vulnerability Predictor

이 프로젝트는 CVE/NVD에 이미 제보된 취약점 설명과, 선택적으로 별도 보관한 취약 코드 샘플을 근거로 대상 소스 코드의 유사 취약 후보를 예측합니다.

## 구조

- `project/src/collectors`: NVD와 GitHub 웹 URL에서 분석 근거를 수집
- `project/src/parser`: NVD 응답을 공통 CVE 모델로 정규화
- `project/src/retrieval`: CVE/취약 코드 샘플과 대상 코드의 유사도 계산
- `project/src/llm`: Markdown 리포트 생성
- `project/src/validation`: 입력값과 결과 검증
- `project/reports`: 생성된 분석 리포트 저장

## 로컬 소스 디렉터리 분석

`--source-dir`에는 리포트 파일이 아니라 실제 `.c`, `.h`, `.cpp`, `.py` 같은 소스 파일이 들어 있어야 합니다.

```powershell
cd project
python -m src.main "openssl" --source-dir reports --limit 20
```

## 이전 제보 취약 코드 샘플과 비교

`--vuln-code-dir`에는 과거에 취약점으로 제보된 코드 파일을 넣습니다. 이 옵션을 주면 CVE 설명뿐 아니라 코드 대 코드 유사도도 함께 반영합니다.

```powershell
cd project
python -m src.main "modsecurity" --source-dir reports --vuln-code-dir known_vulnerable_samples --limit 20
```

## Ollama qwen2.5-coder로 상위 후보 재판단

기본 유사도 분석은 로컬에서 실행됩니다. `--use-llm`을 추가하면 유사도 상위 후보만 Ollama 모델에 보내서 실제 취약 가능성, 오탐 가능성, 확인 방법, 권장 조치를 재판단합니다.

```powershell
cd project
ollama pull qwen2.5-coder
python -m src.main "modsecurity" --source-dir reports --limit 20 --max-findings 10 --use-llm --llm-max-findings 5
```

다른 Ollama 모델이나 URL을 쓰려면 환경 변수 또는 옵션으로 지정할 수 있습니다.

```powershell
$env:OLLAMA_MODEL="qwen2.5-coder"
$env:OLLAMA_URL="http://localhost:11434"
python -m src.main "modsecurity" --source-dir reports --use-llm --llm-model "qwen2.5-coder"
```

OpenAI를 쓰고 싶을 때만 선택적으로 `requirements.txt`를 설치하고 provider를 바꿉니다.

```powershell
pip install -r requirements.txt
$env:OPENAI_API_KEY="your-api-key"
python -m src.main "modsecurity" --source-dir reports --use-llm --llm-provider openai --llm-model "gpt-4o"
```

## GitHub URL을 바로 분석

GitHub 파일, tree, repository URL을 넣으면 소스를 저장하지 않고 유사도 분석 리포트를 생성합니다. 키워드를 생략하면 GitHub 저장소 이름을 NVD 검색 키워드로 사용합니다.

```powershell
cd project
python -m src.main "openssl" --github-url "https://github.com/owner/repo/blob/main/src/app.c"
python -m src.main "openssl" --github-url "https://github.com/owner/repo/tree/main/src" --github-max-files 20
python -m src.main --github-url "https://github.com/owasp-modsecurity/ModSecurity/tree/v2.9.11/apache2" --limit 20
```

소스 파일만 저장하려면 명시적으로 `--save-sources`를 사용합니다.

```powershell
cd project
python -m src.main "openssl" --github-url "https://github.com/owner/repo/tree/main/src" --save-sources
```

## 튜닝 옵션

- `--threshold`: 후보로 보고할 최소 유사도. 기본값은 `0.18`
- `--max-findings`: 리포트에 포함할 최대 후보 수. 기본값은 `20`
- `--use-llm`: LLM으로 상위 후보를 재판단
- `--llm-provider`: `ollama` 또는 `openai`. 기본값은 `ollama`
- `--llm-model`: 사용할 LLM 모델. Ollama 기본값은 `qwen2.5-coder`
- `--llm-max-findings`: LLM에 보낼 상위 후보 수. 기본값은 `5`
- `--limit`: NVD에서 가져올 CVE 개수

NVD API 키가 있다면 환경 변수로 설정할 수 있습니다.

```powershell
$env:NVD_API_KEY="your-api-key"
```
