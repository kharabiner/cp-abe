from cp_abe.fading_function import FadingCPABE
from datetime import datetime, timedelta


def main():
    print("IoT 소프트웨어 업데이트 프레임워크 - CP-ABE, Fading Function, 부분 키 갱신")

    # CP-ABE 시스템 초기화
    cpabe = FadingCPABE()
    cpabe.setup()
    cpabe.save_keys()

    # 테스트 IoT 장치 속성
    device_attributes = ["model:A100", "serialNumber:12345", "region:Asia"]

    # 만료 속성 (2023년 12월 31일까지 구독)
    expiry_attributes = {"subscription": "2023-12-31"}

    # 키 생성
    print("\n기기용 키 생성 중...")
    key = cpabe.keygen_with_expiry(device_attributes, expiry_attributes)

    # 소프트웨어 업데이트 패키지
    update_data = "모델 A100 아시아 지역 기기용 소프트웨어 업데이트 패키지"

    # 업데이트 정책: (model:A100 AND region:Asia) AND subscription:*
    policy = "(model:A100 and region:Asia) and subscription:*"

    # 패키지 암호화
    print("\n업데이트 패키지 암호화 중...")
    ct = cpabe.encrypt_update_package(update_data, policy)

    # 키 유효성 확인
    print("\n키 유효성 검증 중...")
    validity = cpabe.check_key_validity(key)
    print(f"키 유효함: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 패키지 복호화 시도
    print("\n업데이트 패키지 복호화 중...")
    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, key)
        print(f"복호화된 데이터: {decrypted_data}")
    else:
        print("키가 만료되었습니다! 업데이트 패키지를 복호화할 수 없습니다.")

    # 키 갱신 시뮬레이션
    print("\n키 갱신 시뮬레이션...")
    # 새 만료일 (2024년 12월 31일까지)
    new_expiry_attributes = {"subscription": "2024-12-31"}

    # 부분 키 갱신
    updated_key = cpabe.partial_key_update(key, new_expiry_attributes)

    # 갱신된 키 유효성 확인
    validity = cpabe.check_key_validity(updated_key)
    print(f"갱신된 키 유효함: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 패키지 복호화 재시도
    print("\n갱신된 키로 업데이트 패키지 복호화 중...")
    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, updated_key)
        print(f"복호화된 데이터: {decrypted_data}")
    else:
        print("키가 여전히 만료되었습니다! 업데이트 패키지를 복호화할 수 없습니다.")


if __name__ == "__main__":
    main()
