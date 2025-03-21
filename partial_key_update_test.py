from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.fading_functions import LinearFadingFunction
import time
import json
import copy
import base64


def copy_cpabe_key(key):
    """
    CP-ABE 키 객체를 안전하게 복사하는 함수
    charm-crypto의 Element 객체를 적절하게 처리합니다.
    """
    if not isinstance(key, dict):
        return key  # 딕셔너리가 아니면 그대로 반환

    # 새 키 객체 생성
    new_key = {}

    # 기본 메타데이터 복사
    for k in ["user_id", "issue_time", "dynamic_attributes", "update_history"]:
        if k in key:
            if k == "dynamic_attributes" or k == "update_history":
                # 단순 딕셔너리는 일반적인 deepcopy로 충분
                new_key[k] = copy.deepcopy(key[k])
            else:
                new_key[k] = key[k]

    # pairing.Element 객체가 들어있는 부분은 참조만 복사
    # 실제 암호화 작업에서는 이 객체들이 변경되지 않음
    for k, v in key.items():
        if k not in new_key:  # 이미 처리된 항목 건너뛰기
            # Element 객체나 특수 객체는 참조만 복사
            new_key[k] = v

    return new_key


def test_partial_key_update():
    """
    부분 키 갱신 메커니즘을 검증하는 테스트
    - 키 구조의 분석
    - 정적 속성 보존 확인
    - 동적 속성만 갱신되는지 확인
    """
    print("\n===== 부분 키 갱신 메커니즘 검증 테스트 =====")

    # 시스템 초기화
    cpabe = DynamicCPABE()
    cpabe.setup()

    # 테스트용 페이딩 함수 등록
    subscription_function = LinearFadingFunction("subscription", 5)  # 5초 후 만료
    cpabe.register_fading_function("subscription", subscription_function)

    # 사용자 생성
    user_id = cpabe.create_user_record("test_user")
    print(f"사용자 생성: {user_id}")

    # 다양한 속성으로 초기 키 생성
    attributes = ["model", "region", "subscription"]
    key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)
    print("\n초기 키 생성:")
    print_key_structure(key)

    # 초기 키 복사 (비교용) - 안전한 복사 함수 사용
    original_key_attrs = {}
    if "dynamic_attributes" in key:
        original_key_attrs = copy.deepcopy(key["dynamic_attributes"])

    print("\n키의 동적 속성 저장 (참조용):")
    for attr, value in original_key_attrs.items():
        print(f"  - {attr}: {value}")

    # 시간 경과 시뮬레이션 (구독 만료)
    print("\n시간 경과 시뮬레이션 (6초)...")
    time.sleep(6)

    # 만료 확인
    validity = cpabe.check_key_validity(key)
    print(f"\n만료 상태: {validity}")

    # 특정 속성만 갱신
    print("\n'subscription' 속성만 갱신:")
    new_attr = cpabe.update_attribute(user_id, "subscription")
    print(f"새 속성 값: {new_attr['attribute_value']}")

    # 키 병합 전 상태 저장 - 동적 속성만 저장
    before_merge_attrs = {}
    if "dynamic_attributes" in key:
        before_merge_attrs = copy.deepcopy(key["dynamic_attributes"])

    # 부분 키 갱신
    updated_key = cpabe.merge_attribute_to_key(key, new_attr)
    print("\n갱신된 키 구조:")
    print_key_structure(updated_key)

    # 부분 갱신 검증 - 저장된 속성 값만 비교
    print("\n[부분 갱신 검증]")
    print("1. 동적 속성만 변경되었는지 확인:")
    for attr in updated_key["dynamic_attributes"]:
        if attr == "subscription":
            old_val = before_merge_attrs.get(attr, "없음")
            new_val = updated_key["dynamic_attributes"][attr]
            print(f"  - {attr}: {old_val} -> {new_val}")
            if old_val == new_val:
                print("    오류: 구독 속성이 갱신되지 않음!")
        else:
            old_val = original_key_attrs.get(attr, "없음")
            new_val = updated_key["dynamic_attributes"][attr]
            print(f"  - {attr}: {old_val} -> {new_val}")
            if old_val != new_val:
                print("    오류: 정적 속성이 변경됨!")

    # 갱신된 키 유효성 검사
    validity = cpabe.check_key_validity(updated_key)
    print(f"\n갱신 후 키 유효성: {validity}")

    # 암호화/복호화 테스트로 실제 기능 확인
    print("\n[암호화/복호화 테스트]")
    message = "부분 키 갱신 후에도 정상 작동해야 합니다"

    # 다양한 정책으로 암호화
    policies = [
        ["model"],  # 정적 속성만
        ["subscription"],  # 동적 속성만
        ["model", "subscription"],  # 정적 + 동적
        ["model", "region"],  # 정적 속성들
    ]

    for policy in policies:
        policy_str = " AND ".join(policy)
        print(f"\n정책: {policy_str}")

        # 암호화
        ct = cpabe.encrypt_with_dynamic_attributes(message, policy)

        # 복호화 시도
        try:
            decrypted = cpabe.decrypt(ct, updated_key)
            print(f"복호화 성공: {decrypted}")
        except Exception as e:
            print(f"복호화 실패: {e}")


def print_key_structure(key):
    """키 구조 분석 및 출력"""
    # 메타데이터 출력
    print("  메타데이터:")
    for k in ["user_id", "issue_time"]:
        if k in key:
            print(f"    - {k}: {key[k]}")

    # 동적 속성 출력
    if "dynamic_attributes" in key:
        print("  동적 속성:")
        for attr, value in key["dynamic_attributes"].items():
            print(f"    - {attr}: {value}")

    # 키 컴포넌트 분석 (CP-ABE 키 구조 이해)
    print("  키 컴포넌트 분석:")
    component_types = {}

    for k in key:
        if k not in ["dynamic_attributes", "user_id", "issue_time", "update_history"]:
            prefix = k.split("_")[0] if "_" in k else k
            if prefix not in component_types:
                component_types[prefix] = 0
            component_types[prefix] += 1

    for prefix, count in component_types.items():
        print(f"    - {prefix}: {count}개 컴포넌트")


if __name__ == "__main__":
    test_partial_key_update()
