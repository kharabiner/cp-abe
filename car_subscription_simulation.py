from cp_abe.key_authority import KeyAuthority
from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.fading_functions import LinearFadingFunction
import time
from datetime import datetime
import json


def car_subscription_simulation():
    """
    자동차 구독 서비스 시뮬레이션:
    1. 정적 속성(모델=K5)과 동적 속성(구독=x)으로 출고
    2. 구독 시작하면 부분키 갱신으로 구독=o 활성화
    3. 구독 만료 후에도 모델=K5 관련 기능은 계속 사용 가능
    """
    print("\n===== 자동차 구독 서비스 시뮬레이션 =====")

    # CP-ABE 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 5초 후 만료되는 구독 속성 등록
    subscription_function = LinearFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)

    # 인증 기관 초기화
    auth_agency = KeyAuthority(cpabe)

    # 콘텐츠 준비: 구독이 필요한 콘텐츠와 모델만 필요한 콘텐츠
    premium_content = {
        "내비게이션_실시간_업데이트": "최신 교통 정보와 우회로 제안",
        "스트리밍_서비스": "고품질 음악 및 동영상 스트리밍",
        "원격_시동_서비스": "스마트폰으로 원격 시동 및 온도 조절",
    }

    basic_content = {
        "기본_내비게이션": "기본 지도 및 경로 안내",
        "차량_진단": "기본 차량 상태 진단 정보",
        "사용자_매뉴얼": "전자식 사용자 매뉴얼 및 가이드",
    }

    # 콘텐츠 암호화
    print("\n[1단계] 콘텐츠 암호화")

    # 프리미엄 콘텐츠: 모델과 구독 모두 필요
    encrypted_premium = {}
    for name, content in premium_content.items():
        policy = ["model", "subscription"]
        encrypted_premium[name] = cpabe.encrypt_with_dynamic_attributes(content, policy)
        print(f"프리미엄 콘텐츠 '{name}' 암호화 완료")

    # 기본 콘텐츠: 모델만 필요
    encrypted_basic = {}
    for name, content in basic_content.items():
        policy = ["model"]  # 구독 없이 모델만으로 접근 가능
        encrypted_basic[name] = cpabe.encrypt_with_dynamic_attributes(content, policy)
        print(f"기본 콘텐츠 '{name}' 암호화 완료")

    # 차량 출고 시뮬레이션
    print("\n[2단계] 차량 출고 (구독 없이 모델=K5)")
    car_id = "K5-2023-12345"

    # 초기에는 구독 없이 모델 속성만 설정
    initial_attributes = ["model"]  # 모델=K5

    # 차량 등록 (구독 상태: 비활성)
    car_key = auth_agency.register_device(car_id, initial_attributes, 0)  # 구독 일수 0
    print(f"차량 출고 완료: {car_id} (모델: K5, 구독: 비활성)")

    # 실시간 모니터링 시작
    print("\n[3단계] 차량 키 유효성 실시간 모니터링 시작")

    # 초기 상태 확인 - 기본 기능만 접근 가능해야 함
    validity = cpabe.check_key_validity(car_key)
    print(f"\n초기 상태 - 키 유효함: {validity['valid']}")
    print(f"사용 가능한 속성: {validity['valid_attrs']}")

    print("\n기본 콘텐츠 접근 테스트:")
    for name, encrypted in encrypted_basic.items():
        try:
            decrypted = cpabe.decrypt(encrypted, car_key)
            print(f"  '{name}' 접근 성공: {decrypted}")
        except Exception as e:
            print(f"  '{name}' 접근 실패: {e}")

    print("\n프리미엄 콘텐츠 접근 테스트 (실패 예상):")
    for name, encrypted in encrypted_premium.items():
        try:
            decrypted = cpabe.decrypt(encrypted, car_key)
            print(f"  '{name}' 접근 성공: {decrypted}")
        except Exception as e:
            print(f"  '{name}' 접근 실패: 구독 필요")

    # 구독 활성화 시뮬레이션
    print("\n[4단계] 구독 서비스 활성화 (5초 구독)")
    print("사용자: 5초 구독 서비스 신청")
    print("인증 기관: 구독 속성 갱신 중...")

    # 구독 속성 추가
    renewal_result = auth_agency.request_attribute_renewal(car_id, "subscription")

    if renewal_result["success"]:
        new_attr = renewal_result["attribute"]
        car_key = cpabe.merge_attribute_to_key(car_key, new_attr)
        print("구독 활성화 완료")

        # 구독 상태 확인
        validity = cpabe.check_key_validity(car_key)
        print(f"\n구독 활성화 후 - 키 유효함: {validity['valid']}")
        print(f"사용 가능한 속성: {validity['valid_attrs']}")

        # 프리미엄 콘텐츠 접근 테스트 (이제 성공해야 함)
        print("\n구독 활성화 상태에서 프리미엄 콘텐츠 접근:")
        for name, encrypted in encrypted_premium.items():
            try:
                decrypted = cpabe.decrypt(encrypted, car_key)
                print(f"  '{name}' 접근 성공: {decrypted}")
            except Exception as e:
                print(f"  '{name}' 접근 실패: {e}")

    # 구독 만료 대기 및 모니터링
    print("\n[5단계] 실시간 구독 상태 모니터링 (7초 동안)")
    start_time = time.time()

    while time.time() - start_time < 7:  # 7초 동안 모니터링
        elapsed = time.time() - start_time

        validity = cpabe.check_key_validity(car_key)
        subscription_valid = "subscription" in validity["valid_attrs"]

        print(f"\n경과 시간: {elapsed:.1f}초")
        print(f"구독 상태: {'활성' if subscription_valid else '만료'}")
        print(f"키 유효 속성: {validity['valid_attrs']}")

        # 프리미엄 콘텐츠 접근 시도 - 구독 상태에 따라 성공/실패
        test_content = "내비게이션_실시간_업데이트"
        try:
            decrypted = cpabe.decrypt(encrypted_premium[test_content], car_key)
            print(f"  '{test_content}' 접근 성공: {decrypted}")
        except Exception:
            print(f"  '{test_content}' 접근 실패: 구독이 필요하거나 만료됨")

        # 기본 콘텐츠는 항상 접근 가능해야 함
        test_basic = "기본_내비게이션"
        try:
            decrypted = cpabe.decrypt(encrypted_basic[test_basic], car_key)
            print(f"  '{test_basic}' 접근 성공: {decrypted}")
        except Exception as e:
            print(f"  '{test_basic}' 접근 실패(비정상): {e}")

        time.sleep(1)  # 1초마다 체크

    # 최종 상태 확인
    print("\n[6단계] 최종 상태 확인 (구독 만료 후)")
    validity = cpabe.check_key_validity(car_key)
    subscription_valid = "subscription" in validity["valid_attrs"]

    print(f"최종 구독 상태: {'활성' if subscription_valid else '만료'}")
    print(f"사용 가능한 속성: {validity['valid_attrs']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 구독 만료 후 기능 테스트
    print("\n구독 만료 후 프리미엄 콘텐츠 접근 테스트 (실패 예상):")
    for name, encrypted in encrypted_premium.items():
        try:
            decrypted = cpabe.decrypt(encrypted, car_key)
            print(f"  '{name}' 접근 성공(비정상): {decrypted}")
        except Exception:
            print(f"  '{name}' 접근 실패(정상): 구독 만료됨")

    print("\n구독 만료 후 기본 콘텐츠 접근 테스트 (성공 예상):")
    for name, encrypted in encrypted_basic.items():
        try:
            decrypted = cpabe.decrypt(encrypted, car_key)
            print(f"  '{name}' 접근 성공(정상): {decrypted}")
        except Exception as e:
            print(f"  '{name}' 접근 실패(비정상): {e}")


if __name__ == "__main__":
    car_subscription_simulation()
