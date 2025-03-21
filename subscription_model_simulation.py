from cp_abe.key_authority import KeyAuthority
from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.fading_functions import HardExpiryFadingFunction, LinearFadingFunction
import time
from datetime import datetime, timedelta
import json


def simulate_iot_subscription_model():
    """
    IoT 기기 구독 모델 시뮬레이션:
    1. 제조사가 기기 출시 시 CP-ABE 키 탑재 (정적+동적 속성)
    2. 사용자 구독 시작/만료/재구독 시나리오
    3. 오프라인 상태에서도 Fading Function을 통한 구독 만료 보장
    """
    print("\n===== IoT 기기 구독 모델 시뮬레이션 =====")

    # CP-ABE 시스템 초기화 (제조사 환경)
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 오직 동적 속성(구독)에만 페이딩 함수 등록
    # 테스트를 위해 만료 시간 짧게 설정 (5초)
    subscription_function = HardExpiryFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)

    # 정적 속성은 페이딩 함수 등록 필요 없음 (model, region은 정적)

    # 제조사 키 관리 기관 초기화
    manufacturer = KeyAuthority(cpabe)

    # 1. 제조사의 소프트웨어 업데이트 패키지 준비
    update_packages = {
        "security_patch": "중요 보안 업데이트 패키지 v1.2.3",
        "feature_update": "새로운 기능 업데이트 패키지 v2.0.0",
        "firmware": "펌웨어 업데이트 v3.1.4",
    }

    # 2. 소프트웨어 업데이트 접근 정책 설정
    # 모델과 유효한 구독을 요구하는 정책
    policy = ["model", "subscription"]

    # 3. 각 업데이트 패키지 암호화
    encrypted_packages = {}
    for pkg_name, pkg_content in update_packages.items():
        encrypted_packages[pkg_name] = cpabe.encrypt_with_dynamic_attributes(
            pkg_content, policy
        )
        print(f"'{pkg_name}' 패키지 암호화 완료")

    print("\n[1단계] IoT 기기 제조 및 출시")
    # 기기 ID 및 속성 설정
    device_id = "smart-thermostat-xyz123"
    device_attributes = ["model", "region"]

    # 초기 구독 기간 (실제로는 더 길지만, 테스트를 위해 짧게 설정)
    initial_subscription_days = 30
    print(f"초기 구독 기간: {initial_subscription_days}일")

    # 제조사: 새 기기 등록 및 초기 키 발급
    device_key = manufacturer.register_device(
        device_id, device_attributes, initial_subscription_days
    )
    print(f"기기 제조: {device_id} (모델: 스마트 온도조절기, 지역: 아시아)")
    print("CP-ABE 키 탑재 완료 (정적 속성: 모델, 지역 + 동적 속성: 구독)")

    # 4. 기기 유효성 및 업데이트 접근 확인
    print("\n[2단계] 구독 활성화 상태에서 업데이트 접근")
    validity = cpabe.check_key_validity(device_key)
    print(f"구독 상태: {'활성' if validity['valid'] else '만료'}")

    for pkg_name, encrypted_pkg in encrypted_packages.items():
        try:
            decrypted = cpabe.decrypt(encrypted_pkg, device_key)
            print(f"'{pkg_name}' 업데이트 접근 성공: {decrypted}")
        except Exception as e:
            print(f"'{pkg_name}' 업데이트 접근 실패: {e}")

    # 5. 시간 경과로 인한 구독 만료 시뮬레이션
    print("\n[3단계] 시간 경과로 인한 구독 만료 (6초 대기)")
    time.sleep(6)  # 구독 만료 대기

    # 만료 상태 확인
    validity = cpabe.check_key_validity(device_key)
    print(f"구독 상태: {'활성' if validity['valid'] else '만료'}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 업데이트 접근 시도 (실패해야 함)
    try:
        decrypted = cpabe.decrypt(encrypted_packages["security_patch"], device_key)
        print(f"보안 업데이트 접근 성공 (비정상): {decrypted}")
    except Exception:
        print("보안 업데이트 접근 실패 (정상): 구독이 만료되었습니다")

    # 6. 사용자가 재구독
    print("\n[4단계] 사용자 재구독 시뮬레이션")
    print("사용자 → 제조사: 구독 갱신 요청")

    # 구독 갱신 요청
    renewal_result = manufacturer.request_attribute_renewal(device_id, "subscription")

    if renewal_result["success"]:
        print(
            f"제조사 → 사용자: 구독 갱신 승인 (만료일: {renewal_result['expiry_date']})"
        )
        new_attr = renewal_result["attribute"]

        # 기기에서 키 갱신
        device_key = cpabe.merge_attribute_to_key(device_key, new_attr)
        print("기기: 구독 키 갱신 완료")

        # 갱신된 키로 업데이트 접근 확인
        validity = cpabe.check_key_validity(device_key)
        print(f"갱신된 구독 상태: {'활성' if validity['valid'] else '만료'}")

        if validity["valid"]:
            try:
                decrypted = cpabe.decrypt(
                    encrypted_packages["security_patch"], device_key
                )
                print(f"보안 업데이트 접근 성공: {decrypted}")
            except Exception as e:
                print(f"보안 업데이트 접근 실패: {e}")

    # 7. 두 번째 만료 및 재구독
    print("\n[5단계] 두 번째 구독 만료 및 재구독")
    time.sleep(6)  # 다시 구독 만료 대기

    validity = cpabe.check_key_validity(device_key)
    print(f"구독 상태: {'활성' if validity['valid'] else '만료'}")

    if not validity["valid"]:
        print("사용자 → 제조사: 두 번째 구독 갱신 요청")
        renewal_result = manufacturer.request_attribute_renewal(
            device_id, "subscription"
        )

        if renewal_result["success"]:
            print(f"제조사 → 사용자: 두 번째 구독 갱신 승인")
            new_attr = renewal_result["attribute"]
            device_key = cpabe.merge_attribute_to_key(device_key, new_attr)

            # 갱신된 키로 업데이트 접근 확인
            validity = cpabe.check_key_validity(device_key)
            print(f"갱신된 구독 상태: {'활성' if validity['valid'] else '만료'}")

            if validity["valid"]:
                decrypted = cpabe.decrypt(
                    encrypted_packages["feature_update"], device_key
                )
                print(f"기능 업데이트 접근 성공: {decrypted}")

    # 8. 제조사의 기기 지원 종료 시뮬레이션
    print("\n[6단계] 제조사의 기기 지원 종료 시뮬레이션")
    manufacturer.revoke_device(device_id, reason="device_end_of_life")
    print("제조사: 기기 지원 종료 (모든 기술 지원 및 업데이트 중단)")

    # 구독 갱신 시도 (기기 지원 종료로 인해 실패)
    print("사용자 → 제조사: 지원 종료된 기기 구독 갱신 시도")
    renewal_result = manufacturer.request_attribute_renewal(device_id, "subscription")

    if not renewal_result["success"]:
        print(f"제조사 → 사용자: 갱신 거부 (사유: {renewal_result['reason']})")
        print("안내: 해당 기기는 지원이 종료되어 더 이상 업데이트를 받을 수 없습니다")


if __name__ == "__main__":
    simulate_iot_subscription_model()
