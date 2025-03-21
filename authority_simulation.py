from cp_abe.key_authority import KeyAuthority
from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.fading_functions import HardExpiryFadingFunction, LinearFadingFunction
import time
from datetime import datetime, timedelta
import json


def simulate_key_authority():
    """
    키 관리 기관(Key Authority)의 역할 시뮬레이션
    - 기기 등록 및 초기 키 발급
    - 갱신 정책 설정
    - 갱신 요청에 대한 승인 또는 거부
    """
    print("\n===== 키 관리 기관(Key Authority) 시뮬레이션 =====")

    # CP-ABE 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 테스트용 페이딩 함수 설정
    # 5초 후 만료, 최대 2회 갱신 가능
    subscription_function = HardExpiryFadingFunction("subscription", 5, max_renewals=2)
    cpabe.register_fading_function("subscription", subscription_function)

    # 모델 속성은 정적
    model_function = LinearFadingFunction("model", float("inf"))
    cpabe.register_fading_function("model", model_function)

    # 키 관리 기관 초기화
    authority = KeyAuthority(cpabe)

    # 갱신 정책 설정
    authority.set_renewal_policy(
        "subscription",
        max_renewals=2,  # 최대 2회 갱신 가능
        renewal_period_days=30,  # 30일 연장
        blacklisted_devices=["blacklisted-device-001"],  # 차단된 기기
    )

    # 기기 등록 및 초기 키 발급
    print("\n[1단계] 기기 등록 및 초기 키 발급")
    device_id = "iot-device-001"
    key = authority.register_device(device_id, ["model", "subscription"], 30)

    # 기기 정보 확인
    device_info = authority.get_device_info(device_id)
    print(f"기기 정보: {json.dumps(device_info, indent=2)}")

    # 암호화할 메시지
    message = "구독이 유효한 IoT 기기용 펌웨어 업데이트 v1.2.3"
    policy = ["model", "subscription"]

    # 메시지 암호화
    print("\n[2단계] 펌웨어 업데이트 암호화")
    ct = cpabe.encrypt_with_dynamic_attributes(message, policy)
    print("암호화 완료")

    # 초기 키 유효성 및 복호화 테스트
    validity = cpabe.check_key_validity(key)
    print(f"초기 키 유효성: {validity['valid']}")

    if validity["valid"]:
        decrypted = cpabe.decrypt(ct, key)
        print(f"복호화 결과: {decrypted}")
    else:
        print("키가 유효하지 않아 복호화 실패")

    # 시간 경과 시뮬레이션
    print("\n[3단계] 시간 경과 시뮬레이션 (6초 대기)")
    time.sleep(6)  # 6초 대기

    # 키 유효성 재확인 (만료 확인)
    validity = cpabe.check_key_validity(key)
    print(f"\n키 유효성: {validity['valid']}")
    print(f"유효한 속성: {validity['valid_attrs']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 복호화 시도 (실패해야 함)
    try:
        decrypted = cpabe.decrypt(ct, key)
        print(f"복호화 결과: {decrypted}")
    except:
        print("키가 만료되어 복호화 실패")

    # 기기가 인증 기관에 갱신 요청 (IoT 관점)
    print("\n[4단계] 기기가 인증 기관에 갱신 요청")
    print("기기 → 인증 기관: 'subscription' 속성 갱신 요청")

    # 인증 기관 갱신 처리 (서버 관점)
    renewal_result = authority.request_attribute_renewal(device_id, "subscription")

    if renewal_result["success"]:
        print("인증 기관 → 기기: 갱신 승인, 새 속성 발급")
        new_attr = renewal_result["attribute"]
        print(
            f"새 속성 값: {new_attr['attribute_value']}, 만료일: {renewal_result.get('expiry_date')}"
        )

        # 기기가 새 속성을 키에 병합 (갱신)
        key = cpabe.merge_attribute_to_key(key, new_attr)
        print("기기: 키 갱신 완료")

        # 갱신된 키로 복호화 재시도
        validity = cpabe.check_key_validity(key)
        if validity["valid"]:
            decrypted = cpabe.decrypt(ct, key)
            print(f"복호화 성공: {decrypted}")
        else:
            print("갱신 후에도 키가 유효하지 않음")
    else:
        print(f"인증 기관 → 기기: 갱신 거부. 사유: {renewal_result['reason']}")

    # 두 번째 만료 시뮬레이션 및 갱신
    print("\n[5단계] 두 번째 만료 및 갱신 시뮬레이션")
    time.sleep(6)  # 다시 6초 대기

    validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    if not validity["valid"]:
        print("\n기기 → 인증 기관: 두 번째 갱신 요청")
        renewal_result = authority.request_attribute_renewal(device_id, "subscription")

        if renewal_result["success"]:
            print("인증 기관 → 기기: 두 번째 갱신 승인")
            new_attr = renewal_result["attribute"]
            key = cpabe.merge_attribute_to_key(key, new_attr)

            validity = cpabe.check_key_validity(key)
            if validity["valid"]:
                decrypted = cpabe.decrypt(ct, key)
                print(f"복호화 성공: {decrypted}")

    # 세 번째 만료 시뮬레이션 (정책에 의해 갱신 거부되어야 함)
    print("\n[6단계] 세 번째 만료 및 갱신 거부 시뮬레이션")
    time.sleep(6)  # 다시 6초 대기

    validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    if not validity["valid"]:
        print("\n기기 → 인증 기관: 세 번째 갱신 요청")
        renewal_result = authority.request_attribute_renewal(device_id, "subscription")

        if not renewal_result["success"]:
            print(f"인증 기관 → 기기: 갱신 거부. 사유: {renewal_result['reason']}")
            print("정책 제한(최대 갱신 횟수)에 의해 갱신이 거부되었습니다.")

    # 차단된 기기 테스트
    print("\n[7단계] 차단된 기기 시뮬레이션")
    blacklisted_id = "blacklisted-device-001"
    blacklisted_key = authority.register_device(
        blacklisted_id, ["model", "subscription"], 30
    )

    # 갱신 요청 (거부되어야 함)
    renewal_result = authority.request_attribute_renewal(blacklisted_id, "subscription")
    print(f"차단된 기기 갱신 결과: {renewal_result['success']}")
    if not renewal_result["success"]:
        print(f"갱신 거부 사유: {renewal_result['reason']}")

    # 정상 기기 강제 취소
    print("\n[8단계] 기기 접근 권한 취소")
    authority.revoke_device(device_id, reason="subscription_payment_overdue")

    # 취소 후 갱신 요청 (거부되어야 함)
    renewal_result = authority.request_attribute_renewal(device_id, "subscription")
    if not renewal_result["success"]:
        print(f"취소된 기기 갱신 결과: 거부됨 (사유: {renewal_result['reason']})")


if __name__ == "__main__":
    simulate_key_authority()
