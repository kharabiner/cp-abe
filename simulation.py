from cp_abe.fading_function import FadingCPABE
from datetime import datetime, timedelta
import random


def simulate_time_passing():
    """
    시간 경과 시뮬레이션을 위한 테스트 스크립트
    """
    print("\n=== 시간 경과 시뮬레이션 ===")

    # CP-ABE 시스템 초기화
    cpabe = FadingCPABE()
    cpabe.setup()

    # 테스트 IoT 장치 속성 - 간소화
    device_attributes = ["model", "serialNumber", "region"]

    # 현재 날짜로부터 7일 후 만료
    expiry_date = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
    expiry_attributes = {"subscription": expiry_date}

    print(f"구독 만료일 {expiry_date}인 키 생성")

    # 키 생성
    key = cpabe.keygen_with_expiry(device_attributes, expiry_attributes)

    # 업데이트 패키지 및 정책 - 단순화
    update_data = "구독이 유효한 기기를 위한 소프트웨어 업데이트"
    policy = "model and subscription"  # 간소화된 정책
    ct = cpabe.encrypt(update_data, policy)

    # 현재 - 키 유효함
    print("\n1일차: 키가 유효해야 함")
    validity = cpabe.check_key_validity(key)
    print(f"키 유효함: {validity['valid']}")

    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, key)
        print(f"복호화된 데이터: {decrypted_data}")
    else:
        print("키 만료 - 복호화 불가")

    # 시간 경과 시뮬레이션 - 10일 후 (만료됨)
    print("\n10일차: 키가 만료되어야 함")

    # 만료 정보를 직접 수정 - 새 방식
    if "expiry_info" in key:
        # 새 방식: expiry_info에서 직접 만료일을 수정
        for attr in key["expiry_info"]:
            if attr == "subscription":
                # 만료일을 과거로 설정
                key["expiry_info"][attr] = int(
                    (datetime.now() - timedelta(days=3)).timestamp()
                )
                print(
                    f"구독 만료일을 {datetime.fromtimestamp(key['expiry_info'][attr]).strftime('%Y-%m-%d')}로 설정 (과거)"
                )
    else:
        # 이전 방식 (하위 호환성)
        attr_list_key = "orig_attributes" if "orig_attributes" in key else "attr_list"
        for i, attr in enumerate(key[attr_list_key]):
            if "subscription" in attr and ":" in attr:  # 콜론이 있는 경우만
                attr_name, expiry_timestamp = attr.split(":")
                # 만료일을 과거로 설정
                past_date = int((datetime.now() - timedelta(days=3)).timestamp())
                key[attr_list_key][i] = f"{attr_name}:{past_date}"

    validity = cpabe.check_key_validity(key)
    print(f"키 유효함: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, key)
        print(f"복호화된 데이터: {decrypted_data}")
    else:
        print("키 만료 - 복호화 불가")

    # 부분 키 갱신
    print("\n구독 갱신 중...")
    new_expiry_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
    new_expiry_attributes = {"subscription": new_expiry_date}

    updated_key = cpabe.partial_key_update(key, new_expiry_attributes)

    print(f"구독 만료일을 {new_expiry_date}로 업데이트")
    validity = cpabe.check_key_validity(updated_key)
    print(f"키 유효함: {validity['valid']}")

    if validity["valid"]:
        decrypted_data = cpabe.decrypt(ct, updated_key)
        print(f"복호화된 데이터: {decrypted_data}")
    else:
        print("키가 여전히 만료됨 - 복호화 불가")


def test_large_scale():
    """
    대규모 IoT 환경 시뮬레이션
    """
    print("\n=== 대규모 IoT 환경 시뮬레이션 ===")

    cpabe = FadingCPABE()
    cpabe.setup()

    # 다양한 모델과 지역의 IoT 기기
    models = ["A100", "B200", "C300"]
    regions = ["Asia", "Europe", "America"]

    # 업데이트 패키지 준비
    updates = {
        "A100": "A100 모델용 보안 패치 업데이트",
        "B200": "B200 모델용 기능 개선 업데이트",
        "C300": "C300 모델용 버그 수정 업데이트",
    }

    # 각 모델별 정책 - 간소화
    policies = {
        "A100": "model and subscription",
        "B200": "model and subscription",
        "C300": "model and subscription",
    }

    # 각 모델별 업데이트 암호화
    encrypted_updates = {}
    for model, update in updates.items():
        encrypted_updates[model] = cpabe.encrypt(update, policies[model])
        print(f"{model} 모델용 업데이트 암호화 완료")

    # 10개의 IoT 기기 시뮬레이션
    for i in range(10):
        model = models[i % len(models)]
        region = regions[i % len(regions)]
        serial = f"SN{i+1000}"

        # 구독 만료일 - 일부는 유효, 일부는 만료
        if i % 3 == 0:  # 만료된 구독
            expiry_date = (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d")
        else:  # 유효한 구독
            expiry_date = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")

        # 기기 속성 (단순화된 형태)
        device_attrs = ["model", "region", "serialNumber"]  # 콜론(:) 제거
        expiry_attrs = {"subscription": expiry_date}

        # 키 생성
        key = cpabe.keygen_with_expiry(device_attrs, expiry_attrs)

        # 기기 정보 출력
        print(f"\n기기 {i+1}:")
        print(f"  모델: {model}, 지역: {region}, 일련번호: {serial}")
        print(f"  구독 만료일: {expiry_date}")

        # 키 유효성 검사
        validity = cpabe.check_key_validity(key)
        print(f"  키 유효함: {validity['valid']}")

        # 해당 모델의 업데이트 복호화 시도
        if validity["valid"]:
            try:
                decrypted = cpabe.decrypt(encrypted_updates[model], key)
                print(f"  업데이트 수신 성공: {decrypted}")
            except Exception as e:
                print(f"  업데이트 복호화 실패 (정책 불일치): {str(e)}")
        else:
            print("  구독 만료로 업데이트를 수신할 수 없음")

            # 만료된 경우 갱신
            print("  구독 갱신 중...")
            new_expiry = (datetime.now() + timedelta(days=90)).strftime("%Y-%m-%d")
            renewed_key = cpabe.partial_key_update(key, {"subscription": new_expiry})

            # 갱신된 키로 다시 시도
            validity = cpabe.check_key_validity(renewed_key)
            print(f"  갱신된 키 유효함: {validity['valid']}")

            if validity["valid"]:
                try:
                    decrypted = cpabe.decrypt(encrypted_updates[model], renewed_key)
                    print(f"  업데이트 수신 성공: {decrypted}")
                except Exception as e:
                    print(f"  업데이트 복호화 실패 (정책 불일치): {str(e)}")


def test_real_time_expiry():
    """
    실시간 만료 테스트 - 10초 만료 시뮬레이션
    """
    import time

    print("\n=== 실시간 만료 테스트 (10초) ===")

    # CP-ABE 시스템 초기화
    cpabe = FadingCPABE()
    cpabe.setup()

    # 현재 시간 + 10초 만료
    now = datetime.now()
    expiry_date = (now + timedelta(seconds=10)).strftime("%Y-%m-%d %H:%M:%S")

    # 시간 형식 수정 (시분초 포함)
    expiry_timestamp = int((now + timedelta(seconds=10)).timestamp())

    print(f"현재 시간: {now.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"만료 시간: {expiry_date} (10초 후)")

    # 테스트 IoT 장치 속성 - 간소화
    device_attributes = ["model", "serialNumber", "region"]

    # 만료 시간을 초 단위로 설정하기 위해 직접 타임스탬프 사용
    expiry_attrs = {"subscription": expiry_timestamp}

    # 키 생성 (직접 타임스탬프 입력)
    key = cpabe.keygen_with_expiry(device_attributes, {"subscription": expiry_date})

    # 직접 만료 시간 설정 (더 정확한 제어를 위해)
    if "expiry_info" in key:
        key["expiry_info"]["subscription"] = expiry_timestamp

    # 업데이트 패키지 암호화
    update_data = "10초 구독 테스트용 업데이트 패키지"
    policy = "model and subscription"
    ct = cpabe.encrypt(update_data, policy)

    # 실시간 키 상태 확인
    print("\n실시간 키 상태 모니터링 시작 (12초 동안):")
    start_time = time.time()

    while time.time() - start_time < 12:  # 12초 동안 모니터링
        elapsed = time.time() - start_time
        remaining = max(0, 10 - elapsed)

        validity = cpabe.check_key_validity(key)
        status = "유효함" if validity["valid"] else "만료됨"

        print(
            f"경과 시간: {elapsed:.1f}초, 남은 시간: {remaining:.1f}초, 키 상태: {status}"
        )

        # 복호화 시도
        if validity["valid"]:
            decrypted = cpabe.decrypt(ct, key)
            print(f"  복호화 성공: {decrypted}")
        else:
            print("  복호화 실패: 키가 만료되었습니다")

        time.sleep(1)  # 1초마다 확인

    # 최종 상태 확인
    validity = cpabe.check_key_validity(key)
    print(f"\n테스트 완료: 키 유효함 = {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")


if __name__ == "__main__":
    # simulate_time_passing()
    # test_large_scale()
    test_real_time_expiry()  # 실시간 만료 테스트 실행
