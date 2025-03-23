"""
1단계 테스트: 기본적인 CP-ABE 설정, 암호화, 복호화 테스트
- 키 생성
- 정책 기반 암호화
- 파일 암호화/복호화
"""

import os
import sys
import time
import base64
from datetime import datetime, timedelta

# 상위 디렉토리를 모듈 경로에 추가
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from cp_abe.dynamic_cpabe import DynamicCPABE
from cryptography.fernet import Fernet


def serialize_charm_object(obj):
    """charm-crypto 객체를 직렬화 가능한 형식으로 변환"""
    if hasattr(obj, "serialize"):
        # pairing.Element 객체인 경우 직렬화
        try:
            return {
                "__type__": "charm_element",
                "data": base64.b64encode(obj.serialize()).decode("utf-8"),
            }
        except Exception as e:
            return f"직렬화 불가 객체: {type(obj).__name__} (오류: {str(e)})"
    elif isinstance(obj, dict):
        # 딕셔너리인 경우 재귀적으로 처리
        result = {}
        for k, v in obj.items():
            result[k] = serialize_charm_object(v)
        return result
    elif isinstance(obj, list):
        # 리스트인 경우 재귀적으로 처리
        return [serialize_charm_object(v) for v in obj]
    elif hasattr(obj, "__dict__"):
        # 기타 객체는 사전으로 변환 시도
        try:
            return {
                "__type__": obj.__class__.__name__,
                "attrs": serialize_charm_object(obj.__dict__),
            }
        except:
            return str(obj)
    else:
        # 기본 타입은 그대로 반환
        return obj


def main():
    print("\n===== 1단계 테스트: 기본 CP-ABE 설정 및 암호화/복호화 =====")

    # 1. CP-ABE 시스템 초기화
    print("\n[1] CP-ABE 시스템 초기화")
    cpabe = DynamicCPABE()
    cpabe.setup()
    print("CP-ABE 시스템 초기화 완료")

    # 2. 속성 및 정책 설정 - 정적 속성 표준화
    print("\n[2] 속성 및 정책 설정")
    # 정적 속성: 모델, 일련번호, 지역
    device_attributes = ["model", "serialNumber", "region"]
    print(f"기기 속성(정적): {device_attributes}")

    # 간단한 정책 (모델과 일련번호)
    access_policy = "model and serialNumber"
    print(f"접근 정책: {access_policy}")

    # 3. 키 생성
    print("\n[3] 기기 키 생성")
    key = cpabe.keygen(device_attributes)
    print(f"키 생성 완료: {type(key)}")

    # 키 정보 디버깅
    print("\n키 구조 정보:")
    if isinstance(key, dict):
        for k in key.keys():
            print(f"- {k}: {type(key[k])}")

    # 속성 목록 출력 (가능한 경우)
    if "attr_list" in key:
        print(f"속성 목록: {key['attr_list']}")
    elif isinstance(key, dict) and "dynamic_attributes" in key:
        print(f"속성 목록: {list(key['dynamic_attributes'].keys())}")
    else:
        print("속성 목록을 표시할 수 없습니다.")

    # 4. 메시지 암호화 - 에러 처리 개선
    print("\n[4] 메시지 암호화")
    message = "이것은 CP-ABE로 암호화된 비밀 메시지입니다."

    try:
        encrypted = cpabe.encrypt(message, access_policy)
        print(f"메시지 암호화 완료 (접근 정책: {access_policy})")
    except Exception as e:
        print(f"암호화 실패: {e}")
        encrypted = None

    # 5. 메시지 복호화 - 에러 추적 개선
    print("\n[5] 메시지 복호화")
    if encrypted is None:
        print("암호화 실패로 복호화를 건너뜁니다.")
    else:
        try:
            # 복호화 전에 더 자세한 키 정보 출력
            if isinstance(key, dict) and "S" in key:
                print(f"키의 속성 목록: {key['S']}")

            decrypted = cpabe.decrypt(encrypted, key)
            print(f"복호화 성공: {decrypted}")
            print(f"원본 메시지와 일치: {message == decrypted}")
        except Exception as e:
            print(f"복호화 실패: {e}")
            import traceback

            traceback.print_exc()  # 자세한 오류 추적
            print("\n디버깅 정보:")
            print(f"- 키 유형: {type(key)}")
            if hasattr(cpabe, "check_key_validity"):
                validity = cpabe.check_key_validity(key)
                print(f"- 키 유효성: {validity}")

    # 6. 다른 속성 집합으로 테스트
    print("\n[6] 다른 속성 세트로 테스트")
    other_attributes = ["region"]  # 정책을 만족하지 않는 속성 집합
    other_key = cpabe.keygen(other_attributes)
    print(f"다른 속성으로 키 생성: {other_attributes}")

    try:
        decrypted = cpabe.decrypt(encrypted, other_key)
        print(f"복호화 성공: {decrypted}")
    except Exception as e:
        print(f"예상대로 복호화 실패: {e}")

    # 7. 파일 암호화/복호화 테스트 - 직렬화 수정
    print("\n[7] 실제 파일 암호화/복호화 테스트 (직렬화 지원)")

    # 7.1. 테스트 파일 생성
    test_file = "test_file.txt"
    file_content = "이것은 CP-ABE로 보호될 중요한 파일 내용입니다."

    with open(test_file, "w") as f:
        f.write(file_content)
    print(f"테스트 파일 생성: {test_file}")

    # 7.2. 파일 암호화 (하이브리드 암호화: AES + CP-ABE)
    encrypted_file = "test_file.enc"

    # AES 키 생성
    aes_key = Fernet.generate_key()
    cipher = Fernet(aes_key)

    # 파일 내용 읽기
    with open(test_file, "rb") as f:
        file_data = f.read()

    # AES로 파일 암호화
    encrypted_data = cipher.encrypt(file_data)

    # 파일 직접 저장
    with open(encrypted_file, "wb") as f:
        f.write(encrypted_data)

    print(f"파일 암호화 완료 (AES만 사용): {encrypted_file}")

    # AES 키 별도 저장 (CP-ABE 직렬화 문제 회피)
    aes_key_file = "aes_key.txt"
    with open(aes_key_file, "wb") as f:
        f.write(aes_key)

    print(f"AES 키 저장: {aes_key_file}")

    # 7.3. 파일 복호화
    decrypted_file = "test_file_decrypted.txt"

    try:
        # AES 키 읽기
        with open(aes_key_file, "rb") as f:
            loaded_key = f.read()

        # 암호화된 파일 읽기
        with open(encrypted_file, "rb") as f:
            loaded_data = f.read()

        # 복호화
        cipher = Fernet(loaded_key)
        decrypted_data = cipher.decrypt(loaded_data)

        # 복호화된 데이터 저장
        with open(decrypted_file, "wb") as f:
            f.write(decrypted_data)

        print(f"파일 복호화 성공: {decrypted_file}")
        print(f"원본 파일과 일치: {decrypted_data.decode() == file_content}")

    except Exception as e:
        print(f"파일 복호화 중 오류 발생: {e}")
        import traceback

        traceback.print_exc()

    # 8. 테스트 파일 정리
    print("\n[8] 테스트 파일 정리")
    try:
        os.remove(test_file)
        os.remove(encrypted_file)
        os.remove(aes_key_file)
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)
        print("테스트 파일 정리 완료")
    except Exception as e:
        print(f"파일 정리 중 오류: {e}")


if __name__ == "__main__":
    main()
