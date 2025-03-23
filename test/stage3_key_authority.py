"""
3단계 테스트: 키 인증 기관 테스트
- 기기 등록 및 키 발급
- 구독 및 보증 갱신 정책 설정
- 기기 접근 취소
- 갱신 제한 및 블랙리스트 테스트
"""

import os
import sys
import time
from datetime import datetime, timedelta

# 상위 디렉토리를 모듈 경로에 추가
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.key_authority import KeyAuthority
from cp_abe.fading_functions import LinearFadingFunction, HardExpiryFadingFunction


def main():
    print("\n===== 3단계 테스트: 키 인증 기관 테스트 =====")

    # 1. CP-ABE 시스템 초기화
    print("\n[1] CP-ABE 시스템 및 키 인증 기관 초기화")
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 페이딩 함수 등록 (짧은 테스트를 위해)
    subscription_function = LinearFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)

    warranty_function = HardExpiryFadingFunction("warranty", 10, max_renewals=1)
    cpabe.register_fading_function("warranty", warranty_function)

    # 키 인증 기관 초기화
    authority = KeyAuthority(cpabe)
    print("키 인증 기관 초기화 완료")

    # 2. 갱신 정책 설정
    print("\n[2] 갱신 정책 설정")

    # 구독 정책: 무제한 갱신 가능, 기본 30일 갱신
    authority.set_renewal_policy(
        "subscription",
        max_renewals=None,  # 무제한 갱신
        renewal_period_days=30,  # 30일 갱신
        blacklisted_devices=["blacklisted-device-001"],  # 차단된 기기
    )
    print("구독 속성 갱신 정책 설정: 무제한 갱신, 30일 기간")

    # 보증 정책: 최대 1회만 갱신 가능, 1년 갱신
    authority.set_renewal_policy(
        "warranty",
        max_renewals=1,  # 최대 1회 갱신
        renewal_period_days=365,  # 1년 갱신
        blacklisted_devices=["blacklisted-device-001"],  # 차단된 기기
    )
    print("보증 속성 갱신 정책 설정: 최대 1회 갱신, 1년 기간")

    # 3. 기기 등록 및 초기 키 발급
    print("\n[3] 기기 등록 및 초기 키 발급")
    device_ids = ["device-001", "device-002", "blacklisted-device-001"]
    device_keys = {}

    for device_id in device_ids:
        # 정적 속성: 모델, 일련번호
        attributes = ["model", "serialNumber"]

        # 기기 등록 (구독 자동 추가)
        key = authority.register_device(device_id, attributes, 30)
        device_keys[device_id] = key

        print(f"기기 등록: {device_id}, 속성: {attributes} + 구독(30일)")

    # 4. 기기별 정보 확인
    print("\n[4] 기기별 정보 확인")
    for device_id in device_ids:
        device_info = authority.get_device_info(device_id)
        print(f"\n기기 {device_id} 정보:")
        print(f"  등록일: {device_info['registration_date']}")
        print(f"  구독 만료일: {device_info['subscription_end']}")
        print(f"  속성: {device_info['attributes']}")
        print(f"  상태: {device_info['status']}")

    # 5. 암호화된 업데이트 준비
    print("\n[5] 암호화된 업데이트 패키지 준비")

    # 테스트 메시지 및 정책
    update_message = "중요한 보안 업데이트 패키지 v1.2.3"
    policy = ["model", "subscription"]  # 모델과 구독이 필요

    # 메시지 암호화
    encrypted_update = cpabe.encrypt_with_dynamic_attributes(update_message, policy)
    print(f"업데이트 패키지 암호화 완료 (정책: {' AND '.join(policy)})")

    # 6. 기기별 초기 복호화 테스트
    print("\n[6] 기기별 초기 복호화 테스트")
    for device_id, key in device_keys.items():
        print(f"\n기기 {device_id} 복호화 테스트:")
        try:
            validity = cpabe.check_key_validity(key)
            if validity["valid"]:
                decrypted = cpabe.decrypt(encrypted_update, key)
                print(f"  성공: {decrypted}")
            else:
                print(
                    f"  실패: 키가 유효하지 않음 (만료된 속성: {validity['expired_attrs']})"
                )
        except Exception as e:
            print(f"  실패: {str(e)}")

    # 7. 갱신 테스트
    print("\n[7] 갱신 테스트")

    # 정상 기기 갱신 테스트
    normal_device_id = "device-001"
    print(f"\n정상 기기 {normal_device_id} 구독 갱신:")
    renewal_result = authority.request_attribute_renewal(
        normal_device_id, "subscription"
    )

    if renewal_result["success"]:
        print(
            f"  갱신 성공: 새 만료일 {renewal_result.get('expiry_date', '알 수 없음')}"
        )
        new_attr = renewal_result["attribute"]
        device_keys[normal_device_id] = cpabe.merge_attribute_to_key(
            device_keys[normal_device_id], new_attr
        )
    else:
        print(f"  갱신 실패: {renewal_result.get('reason', '알 수 없는 이유')}")

    # 블랙리스트 기기 갱신 테스트
    blacklisted_device_id = "blacklisted-device-001"
    print(f"\n블랙리스트 기기 {blacklisted_device_id} 구독 갱신:")
    renewal_result = authority.request_attribute_renewal(
        blacklisted_device_id, "subscription"
    )

    if renewal_result["success"]:
        print(
            f"  갱신 성공: 새 만료일 {renewal_result.get('expiry_date', '알 수 없음')}"
        )
    else:
        print(f"  갱신 실패: {renewal_result.get('reason', '알 수 없는 이유')}")

    # 8. 기기 취소 테스트
    print("\n[8] 기기 취소 테스트")
    device_to_revoke = "device-002"
    print(f"기기 {device_to_revoke} 취소 중...")

    revocation_success = authority.revoke_device(
        device_to_revoke, reason="subscription_fraud"
    )
    if revocation_success:
        print(f"기기 {device_to_revoke} 취소 성공")

        # 취소된 기기 정보 확인
        device_info = authority.get_device_info(device_to_revoke)
        print(f"  상태: {device_info['status']}")
        print(f"  취소 사유: {device_info.get('revocation_reason', '알 수 없음')}")
        print(f"  취소일: {device_info.get('revocation_date', '알 수 없음')}")
    else:
        print(f"기기 {device_to_revoke} 취소 실패")

    # 9. 취소된 기기 갱신 테스트
    print(f"\n취소된 기기 {device_to_revoke} 구독 갱신 시도:")
    renewal_result = authority.request_attribute_renewal(
        device_to_revoke, "subscription"
    )

    if renewal_result["success"]:
        print(f"  갱신 성공 (비정상): {renewal_result}")
    else:
        print(f"  갱신 실패 (정상): {renewal_result.get('reason', '알 수 없는 이유')}")

    # 10. 갱신 후 복호화 테스트
    print("\n[10] 갱신 후 복호화 테스트")
    for device_id, key in device_keys.items():
        print(f"\n기기 {device_id} 복호화 테스트:")
        try:
            validity = cpabe.check_key_validity(key)
            if validity["valid"]:
                decrypted = cpabe.decrypt(encrypted_update, key)
                print(f"  성공: {decrypted}")
            else:
                print(
                    f"  실패: 키가 유효하지 않음 (만료된 속성: {validity['expired_attrs']})"
                )
        except Exception as e:
            print(f"  실패: {str(e)}")

    # 11. 보증 속성 갱신 제한 테스트
    print("\n[11] 보증 속성 갱신 제한 테스트")
    device_id = "device-001"

    print(f"\n첫 번째 보증 갱신 시도 (정책: 최대 1회 갱신 가능):")
    renewal_result = authority.request_attribute_renewal(device_id, "warranty")

    if renewal_result["success"]:
        print(f"  첫 번째 갱신 성공")
    else:
        print(f"  갱신 실패: {renewal_result.get('reason', '알 수 없는 이유')}")

    print(f"\n두 번째 보증 갱신 시도 (정책 위반 - 실패 예상):")
    renewal_result = authority.request_attribute_renewal(device_id, "warranty")

    if renewal_result["success"]:
        print(f"  두 번째 갱신 성공 (비정상)")
    else:
        print(f"  갱신 실패 (정상): {renewal_result.get('reason', '알 수 없는 이유')}")


if __name__ == "__main__":
    main()
