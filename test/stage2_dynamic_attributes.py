"""
2단계 테스트: 동적 속성 테스트
- 페이딩 함수 등록 및 사용
- 만료되는 구독/보증 속성 테스트
- 부분 키 갱신 테스트
- 실시간 속성 변경 모니터링
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
from cp_abe.fading_functions import LinearFadingFunction, HardExpiryFadingFunction


def main():
    print("\n===== 2단계 테스트: 동적 속성 테스트 =====")

    # 1. CP-ABE 시스템 초기화
    print("\n[1] 동적 CP-ABE 시스템 초기화")
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 2. 페이딩 함수 등록 (짧은 테스트를 위해 시간 단축)
    print("\n[2] 페이딩 함수 등록")

    # 구독 속성: 5초마다 값 변경, 무제한 갱신 가능
    subscription_function = LinearFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)
    print("구독 속성 페이딩 함수 등록: 5초 주기")

    # 보증 속성: 10초 후 만료, 최대 1회만 갱신 가능
    warranty_function = HardExpiryFadingFunction("warranty", 10, max_renewals=1)
    cpabe.register_fading_function("warranty", warranty_function)
    print("보증 속성 페이딩 함수 등록: 10초 후 만료, 최대 1회 갱신")

    # 3. 사용자 및 키 생성
    print("\n[3] 사용자 등록 및 키 생성")
    user_id = cpabe.create_user_record("test_user")

    # 초기 속성: 정적 속성(모델, 일련번호) + 동적 속성(구독, 보증)
    static_attrs = ["model", "serialNumber"]  # 정적 속성: 모델과 일련번호
    dynamic_attrs = ["subscription", "warranty"]  # 동적 속성: 구독과 보증
    all_attrs = static_attrs + dynamic_attrs

    # 키 생성
    key = cpabe.keygen_with_dynamic_attributes(user_id, all_attrs)
    print(f"사용자 ID: {user_id}, 속성: {all_attrs}")
    print(f"동적 속성 현재값: {key.get('dynamic_attributes', {})}")

    # 4. 테스트 메시지 암호화
    print("\n[4] 테스트 메시지 암호화 (다양한 정책)")
    messages = {
        "기본_메시지": "모든 기기에서 접근 가능한 기본 메시지",
        "구독_메시지": "구독이 필요한 프리미엄 콘텐츠",
        "보증_메시지": "보증기간 내 기기만 접근 가능한 서비스 정보",
        "전체_메시지": "구독과 보증이 모두 유효해야 접근 가능한 정보",
    }

    policies = {
        "기본_메시지": ["model"],  # 모델만으로 접근 가능
        "구독_메시지": ["model", "subscription"],  # 모델과 구독 필요
        "보증_메시지": ["model", "warranty"],  # 모델과 보증 필요
        "전체_메시지": [
            "model",
            "subscription",
            "warranty",
        ],  # 모델, 구독, 보증 모두 필요
    }

    encrypted_messages = {}
    for name, msg in messages.items():
        encrypted_messages[name] = cpabe.encrypt_with_dynamic_attributes(
            msg, policies[name]
        )
        print(f"'{name}' 암호화 완료 (정책: {' AND '.join(policies[name])})")

    # 5. 초기 복호화 테스트
    print("\n[5] 초기 복호화 테스트 (모든 속성 유효)")

    # 키 유효성 검사
    validity = cpabe.check_key_validity(key)
    print(f"키 유효함: {validity['valid']}")
    print(f"유효 속성: {validity['valid_attrs']}")
    print(f"만료 속성: {validity['expired_attrs']}")

    # 모든 메시지 복호화 시도
    for name, encrypted in encrypted_messages.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 복호화 성공: {decrypted}")
        except Exception as e:
            print(f"'{name}' 복호화 실패: {e}")

    # 6. 실시간 속성 만료 모니터링
    print("\n[6] 실시간 속성 만료 모니터링 (12초 동안)")
    start_time = time.time()

    # 2초마다 키 유효성 체크
    while time.time() - start_time < 12:
        elapsed = time.time() - start_time
        print(f"\n--- 경과 시간: {elapsed:.1f}초 ---")

        # 키 유효성 검사
        validity = cpabe.check_key_validity(key)
        print(f"키 유효함: {validity['valid']}")
        print(f"유효 속성: {validity['valid_attrs']}")
        print(f"만료 속성: {validity['expired_attrs']}")

        # 보증 메시지 복호화 시도
        try:
            decrypted = cpabe.decrypt(encrypted_messages["보증_메시지"], key)
            print(f"'보증_메시지' 복호화 성공: {decrypted}")
        except Exception:
            print(f"'보증_메시지' 복호화 실패: 보증 기간 만료")

        # 구독 메시지 복호화 시도
        try:
            decrypted = cpabe.decrypt(encrypted_messages["구독_메시지"], key)
            print(f"'구독_메시지' 복호화 성공: {decrypted}")
        except Exception:
            print(f"'구독_메시지' 복호화 실패: 구독 만료")

        time.sleep(2)

    # 7. 부분 키 갱신 테스트
    print("\n[7] 부분 키 갱신 테스트")

    # 보증 속성 갱신
    print("\n보증 속성 갱신 시도:")
    warranty_attr = cpabe.update_attribute(user_id, "warranty")
    key = cpabe.merge_attribute_to_key(key, warranty_attr)
    print(f"보증 속성 갱신 완료, 새 값: {warranty_attr['attribute_value']}")

    # 구독 속성 갱신
    print("\n구독 속성 갱신 시도:")
    subscription_attr = cpabe.update_attribute(user_id, "subscription")
    key = cpabe.merge_attribute_to_key(key, subscription_attr)
    print(f"구독 속성 갱신 완료, 새 값: {subscription_attr['attribute_value']}")

    # 갱신 후 키 유효성 검사
    validity = cpabe.check_key_validity(key)
    print(f"\n갱신 후 키 유효함: {validity['valid']}")
    print(f"유효 속성: {validity['valid_attrs']}")
    print(f"만료 속성: {validity['expired_attrs']}")

    # 8. 갱신 후 새 메시지 암호화 및 복호화 테스트 부분 수정
    print("\n[8] 갱신 후 새 메시지 암호화 및 복호화 테스트")

    # 갱신된 동적 속성 값 확인
    current_subscription = key["dynamic_attributes"].get("subscription", "")
    current_warranty = key["dynamic_attributes"].get("warranty", "")
    print(f"현재 구독 속성 값: {current_subscription}")
    print(f"현재 보증 속성 값: {current_warranty}")

    # 새 메시지
    new_messages = {
        "새_기본_메시지": "갱신 후 접근 가능한 기본 메시지",
        "새_구독_메시지": "갱신된 구독으로 접근 가능한 콘텐츠",
        "새_보증_메시지": "갱신된 보증으로 접근 가능한 서비스 정보",
        "새_전체_메시지": "갱신된 구독과 보증으로 접근 가능한 정보",
    }

    # 수정: modelA 대신 model 사용
    new_policies = {
        "새_기본_메시지": ["model"],  # modelA -> model
        "새_구독_메시지": ["model", current_subscription],
        "새_보증_메시지": ["model", current_warranty],
        "새_전체_메시지": ["model", current_subscription, current_warranty],
    }

    # 새 메시지 암호화
    new_encrypted_messages = {}
    for name, msg in new_messages.items():
        new_encrypted_messages[name] = cpabe.encrypt_with_dynamic_attributes(
            msg, new_policies[name]
        )
        print(f"'{name}' 암호화 완료 (정책: {' AND '.join(new_policies[name])})")

    # 새 메시지 복호화 시도
    print("\n새 메시지 복호화 시도:")
    for name, encrypted in new_encrypted_messages.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 복호화 성공: {decrypted}")
        except Exception as e:
            print(f"'{name}' 복호화 실패: {str(e)}")

    # 9. 이전 메시지 복호화 시도 (실패 예상)
    print("\n[9] 이전 메시지 복호화 시도 (실패 예상)")
    for name, encrypted in encrypted_messages.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 복호화 성공: {decrypted}")
        except Exception as e:
            print(f"'{name}' 복호화 실패: 속성 값 변경으로 인한 불일치")


if __name__ == "__main__":
    main()
