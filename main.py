from cp_abe.fading_function import FadingCPABE
from datetime import datetime, timedelta
import os
import sys


def main():
    print("IoT 소프트웨어 업데이트 프레임워크 - CP-ABE, Fading Function, 부분 키 갱신")

    # CP-ABE 시스템 초기화
    cpabe = FadingCPABE()
    cpabe.setup()
    print("CP-ABE 시스템 초기화 완료")

    # 테스트 IoT 장치 속성
    device_attributes = ["model", "region"]

    # 만료 속성 (현재 날짜로부터 30일)
    future_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    expiry_attributes = {"subscription": future_date}
    print(f"만료일: {future_date}")

    # 키 생성
    print("\n기기용 키 생성 중...")
    try:
        key = cpabe.keygen_with_expiry(device_attributes, expiry_attributes)
        print("키 생성 성공")
    except Exception as e:
        print(f"키 생성 중 오류 발생: {str(e)}")
        sys.exit(1)

    # 소프트웨어 업데이트 패키지
    update_data = "모델 A100 아시아 지역 기기용 소프트웨어 업데이트 패키지"

    # 업데이트 정책: 속성 표현식 단순화
    policy = "(model and region) and subscription"

    # 패키지 암호화
    print("\n업데이트 패키지 암호화 중...")
    ct = cpabe.encrypt_update_package(update_data, policy)
    if ct is None:
        print("암호화에 실패했습니다.")
        sys.exit(1)
    print("패키지 암호화 성공")

    # 키 유효성 확인
    print("\n키 유효성 검증 중...")
    try:
        validity = cpabe.check_key_validity(key)
        print(f"키 유효함: {validity['valid']}")
        print(f"만료된 속성: {validity['expired_attrs']}")
    except Exception as e:
        print(f"키 유효성 검사 중 오류 발생: {str(e)}")
        sys.exit(1)

    # 패키지 복호화 시도
    print("\n업데이트 패키지 복호화 중...")
    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, key)
        if decrypted_data:
            print(f"복호화된 데이터: {decrypted_data}")
        else:
            print("복호화에 실패했습니다.")
    else:
        print("키가 만료되었습니다! 업데이트 패키지를 복호화할 수 없습니다.")

    # 키 갱신 시뮬레이션
    print("\n키 갱신 시뮬레이션...")
    # 새 만료일 (현재 날짜로부터 60일)
    new_expiry_date = (datetime.now() + timedelta(days=60)).strftime("%Y-%m-%d")
    new_expiry_attributes = {"subscription": new_expiry_date}
    print(f"새 만료일: {new_expiry_date}")

    # 부분 키 갱신
    try:
        updated_key = cpabe.partial_key_update(key, new_expiry_attributes)
        print("부분 키 갱신 성공")
    except Exception as e:
        print(f"키 갱신 중 오류 발생: {str(e)}")
        sys.exit(1)

    # 갱신된 키 유효성 확인
    try:
        validity = cpabe.check_key_validity(updated_key)
        print(f"갱신된 키 유효함: {validity['valid']}")
        print(f"만료된 속성: {validity['expired_attrs']}")
    except Exception as e:
        print(f"갱신된 키 유효성 검사 중 오류 발생: {str(e)}")
        sys.exit(1)

    # 패키지 복호화 재시도
    print("\n갱신된 키로 업데이트 패키지 복호화 중...")
    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, updated_key)
        if decrypted_data:
            print(f"복호화된 데이터: {decrypted_data}")
        else:
            print("복호화에 실패했습니다.")
    else:
        print("키가 여전히 만료되었습니다! 업데이트 패키지를 복호화할 수 없습니다.")


if __name__ == "__main__":
    main()
