import ollama
import os
import csv
import json
import re
import time

# ================= 설정 및 경로 =================
BASE_DIR = "burp_out"
RESULT_FILE = "result.csv"
PROCESSED_FILE = "processed.txt"   # 중복 분석 방지용 체크포인트
MODEL_NAME = "llama3.1:8b-instruct-q8_0"
#MODEL_NAME = "qwen3:8b"

# num_ctx 상한 (VRAM/RAM 보호용). llama3.1은 이론상 128K까지 가능하지만
# 8B 양자화 모델 기준 32K~64K 가 현실적. 환경에 맞게 조정.
MAX_NUM_CTX = 32768
MIN_NUM_CTX = 4096
CTX_MARGIN = 2048           # 입력 토큰 추정치에 더할 여유분
CHARS_PER_TOKEN = 3         # 한/영/HTML 혼합 기준 보수적 추정 (1토큰 ≈ 3자)

NUM_PREDICT = 1024          # 출력 임계치 (유지)
MAX_RETRIES = 3             # Ollama 일시 오류 대비 재시도
RETRY_BACKOFF = 2           # 재시도 간 대기(초), 지수 증가
# ============================================


# ---------- 취약점 리스트 (system 프롬프트에 합쳐 KV 캐시 재사용 유도) ----------
VULNERABILITIES_LIST = """\
OS command injection
SQL injection
SQL injection (second order)
File path traversal
File path manipulation
XML external entity injection
XML injection
XML entity expansion
XPath injection
PHP code injection
Server-side JavaScript code injection
Perl code injection
Ruby code injection
Python code injection
Expression Language injection
Unidentified code injection
Server-side template injection
SSI injection
Out-of-band resource load (HTTP)
HTTP request smuggling
Client-side desync
HTTP response header injection
Cross-site scripting (reflected)
Cross-site scripting (stored)
Cross-site request forgery
Open redirection (reflected)
Open redirection (stored)
Broken access control
Serialized object in HTTP message
File upload functionality
GraphQL introspection enabled
GraphQL content type not validated
JWT signature not verified
JWT none algorithm supported
JWT self-signed JWK header supported
JWT weak HMAC secret
JWT arbitrary jku header supported
JWT arbitrary x5u header supported
JWT private key disclosed
Database connection string disclosed
Source code disclosure
Backup file
Private key disclosed
Json Web Key Set disclosed
"""

# ---------- system 프롬프트 (JSON 출력 강제 + 리스트 포함) ----------
SYSTEM_INSTRUCTION = f"""You are an expert web penetration tester.
You analyze the provided HTTP Request and Response and report security vulnerabilities.

[STRICT OUTPUT RULES]
- Output ONLY a single valid JSON object. No prose, no markdown, no code fences.
- Schema:
  {{
    "findings": [
      {{
        "uri": "<full URI from the request line, including query string>",
        "parameter": "<affected parameter name, or empty string if N/A>",
        "method": "<HTTP method, e.g. GET, POST>",
        "vulnerability": "<MUST be one entry copied verbatim from the Vulnerabilities List below>",
        "reason": "<concise evidence-based explanation, single line, no newlines>",
        "probability": <integer 0-100, your confidence>
      }}
    ]
  }}
- If no vulnerabilities are found, output: {{"findings": []}}
- "vulnerability" MUST exactly match one item in the list (case and punctuation included).
- "probability" MUST be an integer between 0 and 100. Do not use words like "high" or "%".
- "reason" MUST be one line and MUST NOT contain newlines or unescaped quotes.
- The Response data may be truncated; analyze what is provided and do not invent content.

[Vulnerabilities List]
{VULNERABILITIES_LIST}"""


# ================= 유틸리티 =================
def ensure_result_file():
    """result.csv가 없으면 헤더만 새로 작성. 있으면 그대로 유지(append)."""
    if not os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(
                ["URI", "Parameter", "Method", "Potential vulnerability", "Reason", "probability"]
            )


def load_processed_set():
    """이미 분석한 request 파일 경로 집합을 로드."""
    if not os.path.exists(PROCESSED_FILE):
        return set()
    with open(PROCESSED_FILE, 'r', encoding='utf-8') as f:
        return {line.strip() for line in f if line.strip()}


def mark_processed(req_path):
    with open(PROCESSED_FILE, 'a', encoding='utf-8') as f:
        f.write(req_path + '\n')


def calc_dynamic_ctx(input_text_len):
    """입력 길이에 비례해 num_ctx를 산정하되 [MIN, MAX]로 클램프."""
    estimated_tokens = input_text_len // CHARS_PER_TOKEN
    desired = estimated_tokens + CTX_MARGIN
    return max(MIN_NUM_CTX, min(MAX_NUM_CTX, desired))


def extract_json(text):
    """모델이 코드블록이나 잡문을 섞어도 JSON 본문만 추출."""
    if not text:
        return None
    # ```json ... ``` 또는 ``` ... ``` 블록 우선 시도
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL | re.IGNORECASE)
    if fence:
        candidate = fence.group(1)
    else:
        # 첫 '{' 부터 마지막 '}' 까지
        start = text.find('{')
        end = text.rfind('}')
        if start == -1 or end == -1 or end <= start:
            return None
        candidate = text[start:end + 1]
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # 흔한 후행 콤마 제거 후 재시도
        cleaned = re.sub(r",\s*([}\]])", r"\1", candidate)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None


def normalize_finding(item):
    """JSON 항목을 CSV 행으로 정규화. 형식이 어긋나면 None."""
    if not isinstance(item, dict):
        return None

    uri = str(item.get("uri", "")).strip()
    parameter = str(item.get("parameter", "")).strip()
    method = str(item.get("method", "")).strip().upper()
    vuln = str(item.get("vulnerability", "")).strip()
    reason = str(item.get("reason", "")).strip().replace('\r', ' ').replace('\n', ' ')

    # probability 정수화
    prob_raw = item.get("probability", "")
    prob_int = None
    if isinstance(prob_raw, (int, float)):
        prob_int = int(prob_raw)
    else:
        m = re.search(r"\d+", str(prob_raw))
        if m:
            prob_int = int(m.group(0))
    if prob_int is None:
        return None
    prob_int = max(0, min(100, prob_int))

    if not uri or not vuln:
        return None

    return [uri, parameter, method, vuln, reason, prob_int]


def call_ollama_with_retry(messages, options):
    """일시적 오류에 대비한 재시도 래퍼."""
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return ollama.chat(
                model=MODEL_NAME,
                messages=messages,
                options=options,
                format="json",   # Ollama JSON mode 강제
                stream=False,
            )
        except Exception as e:
            last_err = e
            wait = RETRY_BACKOFF ** attempt
            print(f"    [!] Ollama 호출 실패(시도 {attempt}/{MAX_RETRIES}): {e} -> {wait}s 후 재시도")
            time.sleep(wait)
    raise last_err


# ================= 메인 루프 =================
def main():
    ensure_result_file()
    processed = load_processed_set()

    # CSV writer를 한 번만 열어 안정적으로 기록
    csv_fp = open(RESULT_FILE, 'a', encoding='utf-8', newline='')
    csv_writer = csv.writer(csv_fp)

    total_pairs = 0
    total_findings = 0
    unmatched_requests = []

    try:
        for root, dirs, files in os.walk(BASE_DIR):
            files.sort()
            file_set = set(files)
            request_files = [f for f in files if f.startswith('request_')]

            for req_file in request_files:
                res_file = req_file.replace('request_', 'response_')
                req_path = os.path.join(root, req_file)
                res_path = os.path.join(root, res_file)

                if res_file not in file_set:
                    unmatched_requests.append(req_path)
                    print(f"[!] 매칭되는 response 없음: {req_path}")
                    continue

                if req_path in processed:
                    print(f"[=] 이미 처리됨, 건너뜀: {req_file}")
                    continue

                total_pairs += 1

                # 입력은 임계치 없이 전체 로드
                with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                    request_data = f.read()
                with open(res_path, 'r', encoding='utf-8', errors='ignore') as f:
                    response_data = f.read()

                input_len = len(request_data) + len(response_data)
                dynamic_ctx = calc_dynamic_ctx(input_len)

                print(f"[*] 분석 중: {req_path}  "
                      f"(req={len(request_data)}B, res={len(response_data)}B, ctx={dynamic_ctx})")

                user_content = (
                    f"[Target Request]\n{request_data}\n\n"
                    f"[Target Response]\n{response_data}"
                )
                messages = [
                    {'role': 'system', 'content': SYSTEM_INSTRUCTION},
                    {'role': 'user', 'content': user_content},
                ]

                options = {
                    'num_ctx': dynamic_ctx,   # 입력에 비례, 단 MAX_NUM_CTX로 보호
                    'num_predict': NUM_PREDICT,  # 출력 임계치 유지
                    'temperature': 0.1,
                    'num_thread': 12,
                    'low_vram': False,
                }

                try:
                    response = call_ollama_with_retry(messages, options)
                    ai_output = response['message']['content'].strip()
                except Exception as e:
                    print(f"    [-] AI 분석 최종 실패 ({req_file}): {e}")
                    continue

                parsed = extract_json(ai_output)
                if not parsed or "findings" not in parsed or not isinstance(parsed["findings"], list):
                    print(f"    [-] JSON 파싱 실패. 원본 일부: {ai_output[:200]!r}")
                    mark_processed(req_path)  # 무한 재시도 방지
                    continue

                findings = parsed["findings"]
                written = 0
                for item in findings:
                    row = normalize_finding(item)
                    if row is None:
                        continue
                    csv_writer.writerow(row)
                    written += 1
                csv_fp.flush()

                total_findings += written
                print(f"    [+] {written}건 기록")
                mark_processed(req_path)

    finally:
        csv_fp.close()

    print()
    print(f"분석 완료. 처리한 쌍: {total_pairs}, 기록된 findings: {total_findings}")
    if unmatched_requests:
        print(f"매칭되지 않은 request {len(unmatched_requests)}개:")
        for p in unmatched_requests:
            print(f"  - {p}")
    print(f"결과 파일: {RESULT_FILE}")
    print(f"체크포인트 파일: {PROCESSED_FILE}")


if __name__ == "__main__":
    main()
