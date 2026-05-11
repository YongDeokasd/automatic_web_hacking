import google.generativeai as genai
import os
import time
import csv

# ================= [1. 설정 구간] =================
API_KEY = "AIzaSyBC4e3dIykjhQVQM0ULola4cGnDsYanEMs"
MODEL_NAME = "gemini-2.5-flash"  # 무료 티어에서 가장 빠르고 효율적임
BASE_DIR = "burp_out"            # 분석할 패킷이 들어있는 폴더
RESULT_FILE = "result.csv"
VULN_FILE = "vulnerabilities.txt"  # 취약점 리스트 파일명
# 무료 티어 속도 제한(15 RPM) 준수를 위해 5초마다 1회 요청
REQUEST_DELAY = 5 
# =================================================

# Gemini API 초기화
genai.configure(api_key=API_KEY)

# 전문가 페르소나 및 지침 설정
system_instruction = """
Act as an expert web penetration tester.
당신은 제공된 Request와 Response를 분석하여 보안 취약점을 찾는 전문가입니다.

[분석 지침]
1. 제공된 취약점 리스트를 참고하여 가장 가능성 높은 취약점을 분류하세요.
2. 결과는 반드시 아래의 CSV 형식을 엄격히 지켜서 출력하세요.
3. 자연어 설명(예: "분석 결과입니다")은 절대 하지 마세요. 오직 CSV 라인만 출력하세요.
4. 취약점이 없거나 확률이 낮으면 Potential vulnerability에 "None" 입력.
5. 헤더나 쿠키에서 취약점 요소가 발견되면 Parameter 칸에 해당 헤더명을 적으세요.

[Output Format]
URI, Parameter, Method, Potential vulnerability, Reason, probability
"""

def load_vulnerabilities():
    """vuln.txt 파일에서 취약점 리스트를 읽어옵니다."""
    if not os.path.exists(VULN_FILE):
        print(f"⚠️ 경고: {VULN_FILE} 파일을 찾을 수 없습니다. 기본 분석을 수행합니다.")
        return "General Web Vulnerabilities"
    
    try:
        with open(VULN_FILE, 'r', encoding='utf-8') as f:
            content = f.read().strip()
            if not content:
                print(f"⚠️ 경고: {VULN_FILE} 파일이 비어 있습니다.")
                return "General Web Vulnerabilities"
            return content
    except Exception as e:
        print(f"[-] {VULN_FILE} 읽기 오류: {e}")
        return "General Web Vulnerabilities"

def initialize_csv():
    if not os.path.exists(RESULT_FILE):
        with open(RESULT_FILE, 'w', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(["URI", "Parameter", "Method", "Potential vulnerability", "Reason", "probability"])

def run_analysis():
    initialize_csv()
    
    # [변경 사항] 파일에서 취약점 리스트 로드
    vulnerabilities_list = load_vulnerabilities()
    
    model = genai.GenerativeModel(
        model_name=MODEL_NAME,
        system_instruction=system_instruction
    )

    print(f"[*] 분석 시작. (Vulnerability List: {VULN_FILE} 사용)")

    for root, dirs, files in os.walk(BASE_DIR):
        files.sort()
        request_files = [f for f in files if f.startswith('request_')]
        
        for req_file in request_files:
            res_file = req_file.replace('request_', 'response_')
            
            if res_file in files:
                req_path = os.path.join(root, req_file)
                res_path = os.path.join(root, res_file)
                
                try:
                    with open(req_path, 'r', encoding='utf-8', errors='ignore') as f:
                        request_data = f.read()
                    with open(res_path, 'r', encoding='utf-8', errors='ignore') as f:
                        response_data = f.read(10000) 
                except Exception as e:
                    print(f"[-] 파일 읽기 오류 ({req_file}): {e}")
                    continue

                print(f"[*] 분석 중: {req_path}...", end="", flush=True)

                try:
                    # 프롬프트 구성 (파일에서 읽은 리스트 포함)
                    prompt = f"[Vulnerabilities List from {VULN_FILE}]\n{vulnerabilities_list}\n\n[Target Request]\n{request_data}\n\n[Target Response]\n{response_data}"
                    
                    response = model.generate_content(
                        prompt,
                        generation_config=genai.types.GenerationConfig(
                            temperature=0.1,
                            max_output_tokens=1024,
                        )
                    )

                    ai_output = response.text.strip()

                    with open(RESULT_FILE, 'a', encoding='utf-8', newline='') as f:
                        for line in ai_output.split('\n'):
                            if ',' in line and not line.startswith('URI'):
                                f.write(line + '\n')
                    
                    print(" [완료]")
                    time.sleep(REQUEST_DELAY)

                except Exception as e:
                    if "429" in str(e):
                        print("\n[!] Rate Limit! 60초 대기...")
                        time.sleep(60)
                    else:
                        print(f"\n[-] API 에러: {e}")
                        time.sleep(2)

if __name__ == "__main__":
    run_analysis()
    print(f"\n✅ 분석 완료. 결과: {RESULT_FILE}")
