"""
4단계 테스트: 실제 응용 시나리오 테스트
- 차량 구독 서비스 시뮬레이션
- 다수 IoT 기기 확장성 테스트
- 오프라인 만료 검증
- 정책 변경 및 속성 추적
"""

import os
import sys
import time
import random
from datetime import datetime, timedelta
import threading
from collections import defaultdict

# 상위 디렉토리를 모듈 경로에 추가
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.key_authority import KeyAuthority
from cp_abe.fading_functions import LinearFadingFunction, HardExpiryFadingFunction


def car_subscription_scenario():
    """차량 서비스 구독 시나리오 시뮬레이션"""
    print("\n===== 차량 서비스 구독 시나리오 =====")

    # 1. 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 페이딩 함수 등록 (테스트를 위한 짧은 시간)
    subscription_function = LinearFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)

    warranty_function = HardExpiryFadingFunction("warranty", 8, max_renewals=1)
    cpabe.register_fading_function("warranty", warranty_function)

    # 인증 기관 초기화
    authority = KeyAuthority(cpabe)

    # 2. 차량 출고 시뮬레이션
    print("\n[1] 차량 출고")
    car_id = "car-123456"

    # 정적 속성: 모델, 일련번호
    static_attrs = ["model", "serialNumber"]

    # 차량 등록 (초기에는 기본 속성만, 구독 없음)
    key = authority.register_device(car_id, static_attrs, 0)  # 구독일 0일
    print(f"차량 출고 완료: {car_id}")
    print(f"기본 속성: {static_attrs}")
    print(f"구독 상태: 비활성")

    # 3. 컨텐츠 준비
    print("\n[2] 컨텐츠 준비")

    contents = {
        "기본_기능": "기본 네비게이션 및 라디오 기능",
        "프리미엄_기능": "실시간 교통 정보 및 음성 비서 기능",
        "정비_정보": "차량 정비 매뉴얼 및 정비소 위치 정보",
    }

    # 정책 설정
    policies = {
        "기본_기능": ["model"],  # 모든 차량에서 사용 가능
        "프리미엄_기능": ["model", "subscription"],  # 구독이 필요함
        "정비_정보": ["model", "warranty"],  # 보증 기간 내에만 사용 가능
    }

    # 컨텐츠 암호화
    encrypted_contents = {}
    for name, content in contents.items():
        encrypted_contents[name] = cpabe.encrypt_with_dynamic_attributes(
            content, policies[name]
        )
        print(f"'{name}' 암호화 완료 (정책: {' AND '.join(policies[name])})")

    # 4. 초기 컨텐츠 접근 테스트
    print("\n[3] 초기 컨텐츠 접근 테스트 (구독 전)")
    validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {validity['valid']}")
    print(f"유효 속성: {validity['valid_attrs']}")

    # 각 컨텐츠 접근 시도
    for name, encrypted in encrypted_contents.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 접근 성공: {decrypted}")
        except Exception as e:
            print(f"'{name}' 접근 실패: 필요한 속성 없음")

    # 5. 구독 시작 시뮬레이션
    print("\n[4] 구독 서비스 활성화")
    print("고객: 프리미엄 서비스 구독 신청")

    # 구독 속성 갱신 요청
    renewal_result = authority.request_attribute_renewal(car_id, "subscription")

    if renewal_result["success"]:
        # 키 갱신
        new_attr = renewal_result["attribute"]
        key = cpabe.merge_attribute_to_key(key, new_attr)
        print(f"구독 속성 추가됨: {new_attr['attribute_value']}")

        # 유효성 확인
        validity = cpabe.check_key_validity(key)
        print(f"키 유효성: {validity['valid']}")
        print(f"유효 속성: {validity['valid_attrs']}")
    else:
        print(f"구독 활성화 실패: {renewal_result.get('reason', '알 수 없는 이유')}")

    # 6. 구독 후 컨텐츠 접근 테스트
    print("\n[5] 구독 후 컨텐츠 접근 테스트")

    # 각 컨텐츠 접근 시도
    for name, encrypted in encrypted_contents.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 접근 성공: {decrypted}")
        except Exception as e:
            print(f"'{name}' 접근 실패: {str(e)}")

    # 7. 시간 경과 시뮬레이션
    print("\n[6] 시간 경과 시뮬레이션 (6초 대기)")
    time.sleep(6)

    # 구독 만료 후 상태 확인
    print("\n[7] 구독 만료 후 상태 확인")
    validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {validity['valid']}")
    print(f"유효 속성: {validity['valid_attrs']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 만료 후 컨텐츠 접근 테스트
    print("\n각 컨텐츠 접근 시도:")
    for name, encrypted in encrypted_contents.items():
        try:
            decrypted = cpabe.decrypt(encrypted, key)
            print(f"'{name}' 접근 성공: {decrypted}")
        except Exception as e:
            if "subscription" in str(e):
                print(f"'{name}' 접근 실패: 구독 만료")
            else:
                print(f"'{name}' 접근 실패: {str(e)}")

    print("\n차량 구독 시나리오 테스트 완료")
    return "차량 구독 테스트 완료"


def scalability_test(num_devices=100):
    """다수 IoT 기기 환경에서의 확장성 테스트"""
    print(f"\n===== 확장성 테스트 ({num_devices}대 기기) =====")

    # 1. 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()
    authority = KeyAuthority(cpabe)

    # 페이딩 함수 등록
    subscription_function = LinearFadingFunction("subscription", 60)  # 60초 주기
    cpabe.register_fading_function("subscription", subscription_function)

    warranty_function = LinearFadingFunction("warranty", 120)  # 120초 주기
    cpabe.register_fading_function("warranty", warranty_function)

    # 2. 사용할 속성들 정의
    # 각 기기마다 고유한 일련번호를 가지도록 설정
    print(f"\n[1] {num_devices}개 기기 등록 중...")
    start_time = time.time()

    # 기기별 키 저장
    device_keys = {}

    for i in range(num_devices):
        # 정적 속성: 모델, 일련번호
        attrs = ["model", f"serialNumber{i+1}"]

        # 기기 ID 생성 및 등록
        device_id = f"device-{i+1:05d}"

        # 50% 확률로 구독 활성화
        subscription_days = 30 if random.random() < 0.5 else 0

        # 기기 등록
        key = authority.register_device(device_id, attrs, subscription_days)
        device_keys[device_id] = key

    registration_time = time.time() - start_time
    print(f"{num_devices}개 기기 등록 완료, 소요 시간: {registration_time:.2f}초")
    print(f"초당 등록 속도: {num_devices / registration_time:.2f}대")

    # 3. 업데이트 패키지 암호화
    print("\n[2] 각 유형별 업데이트 패키지 암호화")

    updates = {
        "기본_업데이트": "모든 기기를 위한 보안 업데이트",
        "구독자_업데이트": "현재 구독 중인 기기를 위한 업데이트",
        "보증_업데이트": "보증 기간 내 기기를 위한 업데이트",
    }

    policies = {
        "기본_업데이트": ["model"],  # 모든 기기용
        "구독자_업데이트": ["model", "subscription"],  # 구독자용
        "보증_업데이트": ["model", "warranty"],  # 보증 기간 내 기기용
    }

    start_time = time.time()
    encrypted_updates = {}

    for name, content in updates.items():
        policy = policies[name]

        # OR 정책 처리 (모든 모델)
        if name == "기본_업데이트":
            policy_str = " OR ".join(policy)
        else:
            policy_str = " AND ".join(policy)

        # 직접 암호화 (정책 문자열 사용)
        encrypted_updates[name] = cpabe.encrypt(content, policy_str)

    encryption_time = time.time() - start_time
    print(f"모든 업데이트 암호화 완료, 소요 시간: {encryption_time:.4f}초")

    # 5. 기기별 업데이트 접근 통계 수집
    print("\n[3] 기기별 업데이트 접근 통계 수집 중...")

    # 통계 저장용 카운터 수정 - 정확한 업데이트 이름 사용
    access_stats = {
        "기본_업데이트": {"성공": 0, "실패": 0},
        "구독자_업데이트": {"성공": 0, "실패": 0},
        "보증_업데이트": {"성공": 0, "실패": 0},
    }

    # 속성별 통계
    attr_stats = defaultdict(lambda: {"기기 수": 0, "접근 성공률": 0})

    # 샘플링 (모든 기기 테스트 시 너무 오래 걸림)
    sample_size = min(100, num_devices)
    sampled_devices = random.sample(list(device_keys.keys()), sample_size)

    for device_id in sampled_devices:
        key = device_keys[device_id]

        # 속성 추출
        device_attrs = []
        if isinstance(key, dict) and "dynamic_attributes" in key:
            device_attrs = list(key["dynamic_attributes"].keys())

        # 각 속성 카운트
        for attr in device_attrs:
            attr_stats[attr]["기기 수"] += 1

        # 각 업데이트 접근 시도 부분 수정
        for update_name, encrypted in encrypted_updates.items():
            try:
                decrypted = cpabe.decrypt(encrypted, key)
                access_stats[update_name]["성공"] += 1

                # 성공한 속성 기록
                for attr in device_attrs:
                    if attr in str(policies[update_name]):
                        attr_stats[attr]["접근 성공률"] += 1

            except Exception:
                access_stats[update_name]["실패"] += 1

    # 평균 계산
    for attr, stats in attr_stats.items():
        if stats["기기 수"] > 0:
            stats["접근 성공률"] = stats["접근 성공률"] / stats["기기 수"] * 100

    # 결과 출력
    print(f"\n샘플 {sample_size}개 기기 기준 업데이트 접근 통계:")
    for update_name, stats in access_stats.items():
        total = stats["성공"] + stats["실패"]
        success_rate = stats["성공"] / total * 100 if total > 0 else 0
        print(f"'{update_name}': 성공률 {success_rate:.1f}% ({stats['성공']}/{total})")

    print("\n속성별 통계:")
    for attr, stats in attr_stats.items():
        if stats["기기 수"] > 0:
            print(
                f"'{attr}': {stats['기기 수']}대 중 접근 성공률 {stats['접근 성공률']:.1f}%"
            )

    print(f"\n확장성 테스트 ({num_devices}대) 완료")
    return f"{num_devices}대 확장성 테스트 완료"


def offline_expiry_test():
    """오프라인 상태에서 속성 만료 테스트"""
    print("\n===== 오프라인 만료 테스트 =====")

    # 1. 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 페이딩 함수 등록 (테스트를 위한 짧은 시간)
    subscription_function = LinearFadingFunction("subscription", 5)
    cpabe.register_fading_function("subscription", subscription_function)

    warranty_function = LinearFadingFunction("warranty", 10)
    cpabe.register_fading_function("warranty", warranty_function)

    # 2. 사용자 및 키 생성
    print("\n[1] 사용자 등록 및 키 생성")
    user_id = cpabe.create_user_record("offline_user")

    # 정적 속성 + 동적 속성
    attributes = ["model", "serialNumber", "subscription", "warranty"]
    key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)
    print(f"사용자 생성: {user_id}, 속성: {attributes}")

    # 3. 콘텐츠 암호화
    print("\n[2] 콘텐츠 암호화")
    content = "이 콘텐츠는 구독이 유효할 때만 접근할 수 있습니다."
    policy = ["model", "subscription"]

    encrypted = cpabe.encrypt_with_dynamic_attributes(content, policy)
    print(f"콘텐츠 암호화 완료 (정책: {' AND '.join(policy)})")

    # 4. 오프라인 시나리오 시뮬레이션
    print("\n[3] 오프라인 시나리오 시뮬레이션")

    # 초기 상태 (온라인)
    print("\n초기 상태 (온라인):")
    validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {validity['valid']}")

    try:
        decrypted = cpabe.decrypt(encrypted, key)
        print(f"콘텐츠 접근 성공: {decrypted}")
    except Exception as e:
        print(f"콘텐츠 접근 실패: {e}")

    # 오프라인 모드 시뮬레이션 (서버 없이 클라이언트만 작동)
    print("\n오프라인 모드 전환...")
    print("기기가 서버에 연결할 수 없는 상태로 전환됨")

    # 시간 경과 (구독 만료)
    print("\n시간 경과 시뮬레이션 (6초)...")
    time.sleep(6)

    # 오프라인 상태에서 만료 검사
    print("\n오프라인 상태에서 유효성 검사:")
    offline_validity = cpabe.check_key_validity(key)
    print(f"키 유효성: {offline_validity['valid']}")
    print(f"유효 속성: {offline_validity['valid_attrs']}")
    print(f"만료 속성: {offline_validity['expired_attrs']}")

    # 만료 후 접근 시도
    print("\n구독 만료 후 콘텐츠 접근 시도:")
    try:
        decrypted = cpabe.decrypt(encrypted, key)
        print(f"콘텐츠 접근 성공 (비정상): {decrypted}")
    except Exception as e:
        print(f"콘텐츠 접근 실패 (정상): {str(e)}")

    print("\n오프라인 만료 테스트 완료 - 서버 연결 없이도 속성이 자동으로 만료됨")
    return "오프라인 만료 테스트 완료"


def main():
    print("\n===== 4단계 테스트: 실제 응용 시나리오 테스트 =====")

    # 1. 차량 구독 서비스 시나리오
    print("\n\n" + "=" * 50)
    print("테스트 1: 차량 구독 서비스 시나리오")
    print("=" * 50)
    result1 = car_subscription_scenario()

    # 2. 다수 IoT 기기 확장성 테스트 (기기 수 조정 가능)
    print("\n\n" + "=" * 50)
    print("테스트 2: 확장성 테스트")
    print("=" * 50)
    result2 = scalability_test(num_devices=100)  # 기기 수 조정 가능

    # 3. 오프라인 만료 테스트
    print("\n\n" + "=" * 50)
    print("테스트 3: 오프라인 만료 테스트")
    print("=" * 50)
    result3 = offline_expiry_test()

    # 결과 요약
    print("\n\n" + "=" * 50)
    print("테스트 결과 요약")
    print("=" * 50)
    print(f"1. 차량 구독 서비스 시나리오: {result1}")
    print(f"2. 확장성 테스트: {result2}")
    print(f"3. 오프라인 만료 테스트: {result3}")


if __name__ == "__main__":
    main()
