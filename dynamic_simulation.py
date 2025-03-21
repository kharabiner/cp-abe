from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.fading_functions import LinearFadingFunction
from datetime import datetime, timedelta
import time
import json


def test_dynamic_attributes():
    """
    페이딩 함수 기반 동적 속성 테스트
    """
    print("\n===== 동적 속성 기반 CP-ABE 테스트 =====")

    # 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 특별한 페이딩 함수 설정 - 짧은 테스트를 위해
    test_subscription = LinearFadingFunction("subscription", 10)  # 10초마다 값이 변경됨
    cpabe.register_fading_function("subscription", test_subscription)

    # 모델 속성은 정적
    static_model = LinearFadingFunction("model", float("inf"))  # 변경되지 않음
    cpabe.register_fading_function("model", static_model)

    # 사용자 생성
    user_id = cpabe.create_user_record("test_user")
    print(f"사용자 ID: {user_id}")

    # 초기 속성 세트로 키 생성
    attributes = ["model", "subscription"]
    key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)
    print("\n초기 키 생성:")
    print(f"속성 값: {json.dumps(key['dynamic_attributes'], indent=2)}")

    # 메시지 암호화
    message = "모델과 유효한 구독이 있는 기기용 기밀 업데이트"
    policy = ["model", "subscription"]
    ct = cpabe.encrypt_with_dynamic_attributes(message, policy)
    print("\n메시지 암호화 완료")

    # 유효성 검사
    validity = cpabe.check_key_validity(key)
    print("\n초기 키 유효성:")
    print(f"유효함: {validity['valid']}")
    print(f"유효한 속성: {validity['valid_attrs']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    # 복호화 시도
    if validity["valid"]:
        decrypted = cpabe.decrypt(ct, key)
        print(f"복호화 성공: {decrypted}")
    else:
        print("키가 유효하지 않습니다. 복호화 실패!")

    # 시간 경과 시뮬레이션 - 12초 동안 2초마다 키 상태 확인
    print("\n실시간 속성 페이딩 시뮬레이션 시작:")
    start_time = time.time()

    while time.time() - start_time < 12:
        elapsed = time.time() - start_time
        print(f"\n{elapsed:.1f}초 경과:")

        # 키 유효성 검사
        validity = cpabe.check_key_validity(key)
        print(f"키 유효함: {validity['valid']}")
        print(f"유효한 속성: {validity['valid_attrs']}")
        print(f"만료된 속성: {validity['expired_attrs']}")

        # 키가 여전히 유효한 경우 복호화 시도
        if validity["valid"]:
            try:
                decrypted = cpabe.decrypt(ct, key)
                print(f"복호화 성공: {decrypted}")
            except Exception as e:
                print(f"복호화 실패: {e}")
        else:
            print("키가 만료되어 복호화 불가능")

            # 만료된 속성 갱신
            if "subscription" in validity["expired_attrs"]:
                print("\n만료된 subscription 속성 갱신 중...")
                new_attr = cpabe.update_attribute(user_id, "subscription")
                print(f"새 속성 값: {new_attr['attribute_value']}")

                # 갱신된 속성을 기존 키에 병합
                key = cpabe.merge_attribute_to_key(key, new_attr)
                print("키 갱신 완료")

                # 갱신된 키로 다시 복호화 시도
                validity = cpabe.check_key_validity(key)
                if validity["valid"]:
                    decrypted = cpabe.decrypt(ct, key)
                    print(f"갱신된 키로 복호화 성공: {decrypted}")
                else:
                    print("갱신 후에도 키가 여전히 유효하지 않음")

        time.sleep(2)  # 2초 대기

    print("\n실시간 페이딩 테스트 완료")

    # 최종 키 상태 확인
    validity = cpabe.check_key_validity(key)
    print("\n최종 키 상태:")
    print(f"유효함: {validity['valid']}")
    print(f"유효한 속성: {validity['valid_attrs']}")
    print(f"만료된 속성: {validity['expired_attrs']}")


if __name__ == "__main__":
    test_dynamic_attributes()
