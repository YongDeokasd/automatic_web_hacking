import xml.etree.ElementTree as ET
import base64
import os
import re

# ================= 설정 구간 =================
EXCLUDE_JS = True  # True: .js 제외 실행 (ON), False: 모두 저장 (OFF)
# ============================================

def sanitize_folder_name(path):
    """URI 경로를 운영체제에서 허용하는 안전한 폴더명으로 변환."""
    if not path or path == "/":
        return "root"
    path = path.strip("/")
    # 윈도우/리눅스 예약 문자 및 특수문자 제거
    path = re.sub(r'[\\:*"<>|?]', '_', path)
    return path

def save_burp_items_to_folders(xml_file, base_output_dir="burp_out"):
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()

        if not os.path.exists(base_output_dir):
            os.makedirs(base_output_dir)

        count = 0
        skipped = 0

        for i, item in enumerate(root.findall('item'), 1):
            # 1. 확장자 체크 (필터링 로직)
            ext_node = item.find('extension')
            extension = ext_node.text.lower() if ext_node is not None and ext_node.text else ""
            
            if EXCLUDE_JS and extension == 'js':
                skipped += 1
                continue
            if EXCLUDE_JS and extension == 'svg':
                skipped += 1
                continue

            # 2. URI 경로 추출 및 폴더 생성
            raw_path = item.find('path').text if item.find('path') is not None else "unknown"
            folder_path = os.path.join(base_output_dir, sanitize_folder_name(raw_path))
            
            os.makedirs(folder_path, exist_ok=True)

            # 3. Request/Response 데이터 추출 및 저장
            for data_type in ['request', 'response']:
                node = item.find(data_type)
                if node is not None and node.text:
                    content = node.text
                    if node.get('base64') == 'true':
                        try:
                            # 바이너리 데이터 포함 가능성을 고려해 디코딩 시도
                            decoded_data = base64.b64decode(content)
                            try:
                                content = decoded_data.decode('utf-8')
                                mode = 'w'
                            except UnicodeDecodeError:
                                content = decoded_data
                                mode = 'wb'
                        except Exception:
                            continue # 데이터 손상 시 스킵

                    filename = f"{data_type}_{i:03d}.txt"
                    file_full_path = os.path.join(folder_path, filename)
                    
                    if mode == 'w':
                        with open(file_full_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    else:
                        with open(file_full_path, 'wb') as f:
                            f.write(content)
            
            count += 1

        print(f"작업 완료")
        print(f"- 저장된 항목: {count}개")
        print(f"- 제외된 .js 항목: {skipped}개 (필터 {'ON' if EXCLUDE_JS else 'OFF'})")
        print(f"- 저장 위치: {os.path.abspath(base_output_dir)}")

    except Exception as e:
        print(f"오류 발생: {e}")

if __name__ == "__main__":
    xml_filename = 'test2'  # 원본 XML 파일명
    save_burp_items_to_folders(xml_filename)