from cp_abe.iot_cpabe import IoTCPABE
from cp_abe.fading_function import FadingCPABE  # FadingCPABE 임포트
from cp_abe.fading_functions import (
    FadingFunction,
    LinearFadingFunction,
    LocationFadingFunction,
)
from charm.toolbox.pairinggroup import ZR
from datetime import datetime
import time
import uuid
import json
import os


class DynamicCPABE(FadingCPABE):  # IoTCPABE 대신 FadingCPABE 상속
    """
    논문의 Dynamic Attribute Based Encryption(DABE) 구현
    - 각 속성이 독립적인 페이딩 함수를 가짐
    - 개별 속성 갱신 지원
    - 사용자 프로필 기반 키 관리
    """

    def __init__(self):
        super().__init__()
        self.user_records = {}  # 사용자 레코드 저장 (Key Master)
        self.fading_functions = {}  # 속성별 페이딩 함수

    def register_fading_function(self, attribute_name, fading_function):
        """
        시스템에 새 페이딩 함수 등록
        """
        self.fading_functions[attribute_name] = fading_function

    def setup_default_fading_functions(self):
        """
        기본 페이딩 함수 설정
        """
        # 구독 속성: 1일마다 값 변경
        self.register_fading_function(
            "subscription", LinearFadingFunction("subscription", 86400)
        )

        # 위치 속성: 계층에 따라 다른 만료 시간
        self.register_fading_function(
            "location_layer1", LocationFadingFunction("general", 1, 3600)
        )  # 1시간
        self.register_fading_function(
            "location_layer2", LocationFadingFunction("area", 2, 1800)
        )  # 30분
        self.register_fading_function(
            "location_layer3", LocationFadingFunction("specific", 3, 600)
        )  # 10분

        # 모델 속성: 고정 값 (동적으로 변하지 않음)
        self.register_fading_function("model", FadingFunction("model", float("inf")))

    def create_user_record(self, user_id=None):
        """
        새 사용자 레코드 생성 (Key Master 기능)
        """
        if user_id is None:
            user_id = str(uuid.uuid4())

        # 논문에 설명된 대로 각 사용자에 대한 고유한 랜덤 값(r) 생성
        # 실제 CP-ABE 구현에서는 더 복잡한 과정이 필요할 수 있음
        record = {
            "user_id": user_id,
            "random_value": self.group.random(ZR),  # Zr이 아닌 ZR을 사용
            "creation_time": time.time(),
            "attributes": {},  # 사용자의 현재 속성 저장
        }

        self.user_records[user_id] = record
        return user_id

    def compute_attribute_value(self, attribute_name, current_time=None):
        """
        페이딩 함수를 사용하여 현재 속성 값 계산
        """
        # 페이딩 함수가 등록되지 않은 속성은 정적 속성으로 간주
        if attribute_name not in self.fading_functions:
            # 정적 속성은 일관된 값을 반환 (시간에 영향을 받지 않음)
            return f"{attribute_name}_static"

        return self.fading_functions[attribute_name].compute_current_value(current_time)

    def keygen_with_dynamic_attributes(self, user_id, attributes):
        """
        동적 속성이 있는 키 생성
        """
        # 사용자 레코드 확인
        if user_id not in self.user_records:
            user_id = self.create_user_record(user_id)

        user_record = self.user_records[user_id]

        # 모든 속성에 대한 현재 값 계산
        current_attributes = []
        attribute_values = {}

        for attr in attributes:
            current_value = self.compute_attribute_value(attr)
            current_attributes.append(current_value)
            attribute_values[attr] = current_value

        # 기본 CP-ABE 키 생성
        key = self.cpabe.keygen(self.pk, self.mk, current_attributes)

        # 동적 속성 메타데이터 추가
        key["user_id"] = user_id
        key["dynamic_attributes"] = attribute_values
        key["issue_time"] = time.time()

        # 사용자 레코드 업데이트
        user_record["attributes"].update(attribute_values)

        return key

    def update_attribute(self, user_id, attribute_name):
        """
        기존 키의 단일 속성 업데이트 (논문의 핵심 기능)
        """
        if user_id not in self.user_records:
            raise ValueError(f"사용자를 찾을 수 없음: {user_id}")

        if attribute_name not in self.fading_functions:
            raise ValueError(f"정의되지 않은 속성: {attribute_name}")

        user_record = self.user_records[user_id]

        # 속성의 새 값 계산
        new_value = self.compute_attribute_value(attribute_name)

        # 새 속성 생성
        # 실제 구현에서는 사용자 레코드의 랜덤 값을 사용하여 속성 생성
        # 이 예제에서는 단순화를 위해 기본 keygen을 사용
        new_attr_key = self.cpabe.keygen(self.pk, self.mk, [new_value])

        # 사용자 레코드 업데이트
        user_record["attributes"][attribute_name] = new_value

        # 새 속성 반환
        return {
            "attribute_name": attribute_name,
            "attribute_value": new_value,
            "attribute_key": new_attr_key,
            "issue_time": time.time(),
        }

    def check_key_validity(self, key):
        """
        키의 모든 동적 속성의 유효성 검사
        """
        if not isinstance(key, dict) or "dynamic_attributes" not in key:
            # 다른 형식의 키에 대한 하위 호환성 지원
            return super().check_key_validity(key)

        now = time.time()
        valid_attrs = []
        expired_attrs = []

        for attr_name, attr_value in key["dynamic_attributes"].items():
            # 페이딩 함수가 등록되지 않은 속성은 정적으로 간주하고 항상 유효함
            if attr_name not in self.fading_functions:
                valid_attrs.append(attr_name)
                continue

            # 동적 속성의 현재 값 계산 및 비교
            current_value = self.compute_attribute_value(attr_name)
            if attr_value == current_value:
                valid_attrs.append(attr_name)
            else:
                expired_attrs.append(attr_name)

        return {
            "valid": len(expired_attrs) == 0,
            "valid_attrs": valid_attrs,
            "expired_attrs": expired_attrs,
        }

    def merge_attribute_to_key(self, key, new_attribute):
        """
        기존 키에 새로 업데이트된 속성 병합 (정적 속성은 유지하면서 동적 속성만 갱신)
        """
        if not isinstance(key, dict) or "dynamic_attributes" not in key:
            raise ValueError("키가 동적 속성을 지원하지 않음")

        attr_name = new_attribute["attribute_name"]
        attr_value = new_attribute["attribute_value"]
        attr_key = new_attribute["attribute_key"]

        # 1. 동적 속성 메타데이터 갱신
        key["dynamic_attributes"][attr_name] = attr_value

        # 2. 디버그 정보 출력
        print(f"부분 키 갱신: '{attr_name}' 속성을 '{attr_value}'로 갱신")

        # 3. 새 속성 키에서 모든 적절한 컴포넌트 추출
        updated_count = 0

        # 키 컴포넌트 복사 (CP-ABE 알고리즘에 따라 다를 수 있음)
        # BSW07 CP-ABE에서는 D_ 접두사가 있는 컴포넌트가 속성과 관련됨
        for k, v in attr_key.items():
            if isinstance(k, str):
                # CP-ABE 키의 핵심 컴포넌트 복사
                if k.startswith("D_") or k == "D" or k == "Dj" or k == "Djp":
                    key[k] = v
                    updated_count += 1
                    print(f"  키 컴포넌트 갱신: {k}")

        # 4. 갱신 이력 추가
        if "update_history" not in key:
            key["update_history"] = []

        key["update_history"].append(
            {
                "attribute": attr_name,
                "new_value": attr_value,
                "update_time": time.time(),
                "components_updated": updated_count,
            }
        )

        print(f"키 병합 완료: {updated_count}개 컴포넌트 갱신됨")
        return key

    def validate_partial_key_update(self, old_key, updated_key, attribute_name):
        """
        부분 키 갱신이 올바르게 이루어졌는지 검증
        """
        print(f"\n부분 키 갱신 검증: '{attribute_name}' 속성")

        # 1. 기본 검증 - 메타데이터
        if "dynamic_attributes" not in updated_key:
            print("오류: 갱신된 키에 dynamic_attributes 필드가 없음")
            return False

        if attribute_name not in updated_key["dynamic_attributes"]:
            print(f"오류: 갱신된 키에 {attribute_name} 속성이 없음")
            return False

        # 2. 정적 속성 보존 확인
        static_attrs_preserved = True
        if "dynamic_attributes" in old_key:
            for attr, value in old_key["dynamic_attributes"].items():
                if attr != attribute_name:  # 갱신 대상이 아닌 다른 속성들
                    if (
                        attr not in updated_key["dynamic_attributes"]
                        or updated_key["dynamic_attributes"][attr] != value
                    ):
                        print(f"오류: 정적 속성 '{attr}' 값이 보존되지 않음")
                        static_attrs_preserved = False

        # 3. 속성 값 변경 확인
        value_changed = False
        if (
            "dynamic_attributes" in old_key
            and attribute_name in old_key["dynamic_attributes"]
        ):
            old_value = old_key["dynamic_attributes"][attribute_name]
            new_value = updated_key["dynamic_attributes"][attribute_name]
            value_changed = old_value != new_value
            print(f"속성 값 변경: {old_value} -> {new_value}")

        # 4. 키 컴포넌트 비교 (속성별 비교가 가능하다면)
        components_matched = self._compare_key_components(
            old_key, updated_key, attribute_name
        )

        result = static_attrs_preserved and value_changed
        print(f"검증 결과: {'성공' if result else '실패'}")
        print(f"- 정적 속성 보존: {'예' if static_attrs_preserved else '아니오'}")
        print(f"- 속성 값 변경: {'예' if value_changed else '아니오'}")
        print(f"- 키 컴포넌트 분석: {'일치' if components_matched else '불일치'}")

        return result

    def _compare_key_components(self, old_key, new_key, changed_attr):
        """
        두 키의 컴포넌트를 비교하여 특정 속성 관련 부분만 변경되었는지 확인
        """
        # 복잡한 키 구조를 분석해야 하므로 간단한 휴리스틱만 사용
        changed_components = 0
        preserved_components = 0

        # 키에서 문자열 형식의 키만 비교
        for k in set(old_key.keys()) | set(new_key.keys()):
            if isinstance(k, str) and k not in [
                "dynamic_attributes",
                "user_id",
                "issue_time",
                "update_history",
            ]:
                if k in old_key and k in new_key:
                    if old_key[k] == new_key[k]:
                        preserved_components += 1
                    else:
                        # 이 컴포넌트가 변경된 속성과 관련있는지 확인
                        attr_base = changed_attr.split("_")[0]
                        if attr_base in k:
                            changed_components += 1
                        else:
                            # 관련 없는 컴포넌트가 변경됨 - 이상 징후
                            print(f"경고: 무관한 컴포넌트 '{k}' 변경됨")
                            return False

        print(
            f"컴포넌트 분석: {changed_components}개 변경, {preserved_components}개 보존"
        )
        return True

    def encrypt_with_dynamic_attributes(self, msg, policy_attributes):
        """
        동적 속성을 고려한 암호화
        """
        # 정책에 사용된 각 속성의 현재 값으로 정책 업데이트
        current_policy = []

        for attr in policy_attributes:
            if attr in self.fading_functions:
                current_value = self.compute_attribute_value(attr)

                # subscription 속성은 특별하게 처리 - 숫자 부분 없이 사용
                if attr == "subscription":
                    # 숫자 없이 base 이름만 사용
                    current_policy.append("subscription")
                else:
                    current_policy.append(current_value)
            else:
                current_policy.append(attr)

        # 표준 암호화 함수 사용
        policy_str = " AND ".join(current_policy)
        print(f"실제 사용 정책: {policy_str}")
        return self.encrypt(msg, policy_str)
