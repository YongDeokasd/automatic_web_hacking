import xml.etree.ElementTree as ET
import base64
import os
import re

# ================= 설정 구간 =================
EXCLUDE_JS = False  # True: .js 제외 (ON), False: 모두 저장 (OFF)
MAX_PATH_LENGTH = 240 # Windows 전체 경로 제한 고려
# ============================================

def sanitize_folder_name(path):
    """
    URI에서 파라미터(=)와 쿼리(?)를 완전히 제거하고 
    순수 폴더 구조만 남깁니다.
    """
    if not path or path == "/":
        return "root"
    
    # 1. 표준 쿼리 스트링(?) 제거
    path = path.split('?')[0]
    
    # 2. 경로 내 파라미터(=) 제거
    # 예: /mpro_prod/do_FILE_ID=SEARCH -> /mpro_prod 만 남김
    if '=' in path:
        # '='가 있는 위치의 앞부분만 취한 뒤, 마지막 '/' 전까지 잘라서 상위 폴더 유지
        path = path.split('=')[0]
        if '/' in path:
            path = path.rsplit('/', 1)[0]
    
    # 3. 양 끝 슬래시 제거 및 특수문자 치환
    path = path.strip("/")
    # 파일 시스템 금지 문자 제거
    path = re.sub(r'[\\:*"<>|?%]', '_', path)
    
    return path if path else "root"

def save_burp_items_to_folders(xml_file, base_output_dir="burp_out"):
    try:
        base_output_dir = os.path.abspath(base_output_dir)
        tree = ET.parse(xml_file)
        root = tree.getroot()

        if not os.path.exists(base_output_dir):
            os.makedirs(base_output_dir)

        count = 0
        skipped = 0

        for i, item in enumerate(root.findall('item'), 1):
            # 확장자 필터
            ext_node = item.find('extension')
            extension = ext_node.text.lower() if ext_node is not None and ext_node.text else ""
            if EXCLUDE_JS and extension == 'js':
                skipped += 1
                continue

            # 경로 파싱
            raw_path = item.find('path').text if item.find('path') is not None else "unknown"
            sanitized_path = sanitize_folder_name(raw_path)
            
            # 윈도우 경로 길이 에러 방지용 안전 장치
            folder_path = os.path.join(base_output_dir, sanitized_path)
            if len(folder_path) > MAX_PATH_LENGTH:
                folder_path = folder_path[:MAX_PATH_LENGTH]

            os.makedirs(folder_path, exist_ok=True)

            # Request/Response 저장
            for data_type in ['request', 'response']:
                node = item.find(data_type)
                if node is not None and node.text:
                    content = node.text
                    is_base64 = (node.get('base64') == 'true')
                    
                    # 파일명은 중복 방지를 위해 인덱스 유지
                    filename = f"{data_type}_{i:03d}.txt"
                    file_full_path = os.path.join(folder_path, filename)
                    
                    try:
                        if is_base64:
                            decoded = base64.b64decode(content)
                            try:
                                with open(file_full_path, 'w', encoding='utf-8') as f:
                                    f.write(decoded.decode('utf-8', errors='ignore'))
                            except:
                                with open(file_full_path, 'wb') as f:
                                    f.write(decoded)
                        else:
                            with open(file_full_path, 'w', encoding='utf-8') as f:
                                f.write(content)
                    except Exception as e:
                        print(f"파일 저장 중 건너뜀 (Index {i}): {e}")
            
            count += 1

        print(f"✅ 필터링 완료!")
        print(f"- 저장된 항목: {count}개")
        print(f"- 제외된 .js: {skipped}개")
        print(f"- 결과 경로: {base_output_dir}")

    except Exception as e:
        print(f"❌ 오류 발생: {e}")

if __name__ == "__main__":
    xml_filename = 'test' 
    save_burp_items_to_folders(xml_filename)
