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
        if attribute_name not in self.fading_functions:
            raise ValueError(f"페이딩 함수가 정의되지 않은 속성: {attribute_name}")

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
            if attr_name not in self.fading_functions:
                # 정의되지 않은 속성은 항상 유효하다고 가정
                valid_attrs.append(attr_name)
                continue

            # 현재 이 속성에 대한 값 계산
            current_value = self.compute_attribute_value(attr_name)

            # 저장된 값과 현재 계산된 값 비교
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
        기존 키에 새로 업데이트된 속성 병합
        """
        if not isinstance(key, dict) or "dynamic_attributes" not in key:
            raise ValueError("키가 동적 속성을 지원하지 않음")

        attr_name = new_attribute["attribute_name"]
        attr_value = new_attribute["attribute_value"]

        # 메타데이터 업데이트
        key["dynamic_attributes"][attr_name] = attr_value

        # 속성 키의 요소를 기존 키에 병합
        # 이 부분은 실제 구현에서 더 복잡할 수 있음
        attr_key = new_attribute["attribute_key"]

        # 키 병합 로직 구현 (단순화 버전)
        # 실제로는 암호학적으로 더 복잡한 병합이 필요할 수 있음
        for k, v in attr_key.items():
            if k.startswith("D_"):
                key[k] = v

        return key

    def encrypt_with_dynamic_attributes(self, msg, policy_attributes):
        """
        동적 속성을 고려한 암호화
        """
        # 정책에 사용된 각 속성의 현재 값으로 정책 업데이트
        current_policy = policy_attributes.copy()

        for i, attr in enumerate(policy_attributes):
            if attr in self.fading_functions:
                current_value = self.compute_attribute_value(attr)
                current_policy[i] = current_value

        # 표준 암호화 함수 사용
        return self.encrypt(msg, " AND ".join(current_policy))
