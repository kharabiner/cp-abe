from .iot_cpabe import IoTCPABE
from charm.toolbox.pairinggroup import ZR
from datetime import datetime
import time
import uuid
import json


class DynamicCPABE(IoTCPABE):
    """
    동적 속성 관리 기능을 갖춘 CP-ABE 구현
    - 정적 속성: 모델, 일련번호 (변하지 않음)
    - 동적 속성: 구독, 보증 (시간에 따라 자동 변경됨)
    """

    def __init__(self):
        super().__init__()
        self.user_records = {}  # 사용자 레코드
        self.fading_functions = {}  # 페이딩 함수

    def register_fading_function(self, attribute_name, fading_function):
        """시스템에 새 페이딩 함수 등록"""
        self.fading_functions[attribute_name] = fading_function

    def create_user_record(self, user_id=None):
        """새 사용자 레코드 생성"""
        if user_id is None:
            user_id = str(uuid.uuid4())

        record = {
            "user_id": user_id,
            "random_value": self.group.random(ZR),
            "creation_time": time.time(),
            "attributes": {},
        }

        self.user_records[user_id] = record
        return user_id

    def compute_attribute_value(self, attribute_name, current_time=None):
        """페이딩 함수로 현재 속성 값 계산"""
        # 페이딩 함수가 등록되지 않은 속성은 정적 속성으로 처리
        if attribute_name not in self.fading_functions:
            return attribute_name  # 수정: 원래 속성 이름 그대로 반환 (suffix 없음)

        return self.fading_functions[attribute_name].compute_current_value(current_time)

    def keygen_with_attributes(self, attributes, expiry_attributes=None):
        """
        정적 및 동적 속성을 모두 포함한 키 생성

        Args:
            attributes: 정적 속성 리스트
            expiry_attributes: 동적 속성 딕셔너리 {속성이름: 만료일자}
        """
        # 기본 속성 설정
        all_attributes = attributes.copy()

        # 만료 속성 정보 저장
        expiry_info = {}

        # 만료 속성이 있는 경우 처리
        if expiry_attributes:
            for attr, expiry in expiry_attributes.items():
                # 타임스탬프로 직접 주어진 경우
                if isinstance(expiry, int):
                    expiry_timestamp = expiry
                else:
                    # 만료일을 timestamp로 변환 - 여러 형식 지원
                    try:
                        # 시분초 포함 형식 시도
                        expiry_timestamp = int(
                            datetime.strptime(expiry, "%Y-%m-%d %H:%M:%S").timestamp()
                        )
                    except ValueError:
                        try:
                            # 날짜만 있는 형식 시도
                            expiry_timestamp = int(
                                datetime.strptime(expiry, "%Y-%m-%d").timestamp()
                            )
                        except ValueError:
                            raise ValueError(f"지원되지 않는 날짜 형식: {expiry}")

                # 속성 목록에 동적 속성 추가
                all_attributes.append(attr)
                # 만료 정보 저장
                expiry_info[attr] = expiry_timestamp

        # 키 생성
        key = self.cpabe.keygen(self.pk, self.mk, all_attributes)

        # 키에 메타데이터 추가
        if isinstance(key, dict):
            key["orig_attributes"] = all_attributes
            key["expiry_info"] = expiry_info
            # 동적 속성 현재값 저장
            key["dynamic_attributes"] = {}
            for attr in attributes:
                key["dynamic_attributes"][attr] = attr  # 정적 속성은 그대로
            for attr in expiry_info:
                key["dynamic_attributes"][attr] = attr  # 동적 속성 초기값

        return key

    def keygen_with_dynamic_attributes(self, user_id, attributes):
        """
        동적 속성이 포함된 키 생성 (정적 + 동적)
        """
        if not self.pk or not self.mk:
            self.setup()

        # 정적 속성만 포함된 기본 집합
        base_attributes = []

        # 동적 속성과 정적 속성 분리
        dynamic_attrs = []

        # 모든 속성을 검사하여 동적 속성 분리 (subscription, warranty)
        for attr in attributes:
            attr_lower = str(attr).lower()  # 소문자로 변환하여 비교

            if attr_lower == "subscription" or attr_lower == "warranty":
                dynamic_attrs.append(attr_lower)
            else:
                base_attributes.append(attr)

        # 기본 키 생성 (정적 속성만 포함)
        key = self.keygen(base_attributes)

        # 키 확장 - 메타데이터 추가
        if isinstance(key, dict):
            key["user_id"] = user_id
            key["issue_time"] = time.time()
            key["dynamic_attributes"] = {}
            key["expiry_info"] = {}

            # 동적 속성 추가
            for attr_name in dynamic_attrs:
                # 현재 값 계산
                attr_value = self.compute_attribute_value(attr_name)

                # 값을 키에 저장
                key["dynamic_attributes"][attr_name] = attr_value

                # 만료 정보 저장
                expiry_time = self.get_attribute_expiry_time(attr_name)
                key["expiry_info"][attr_name] = {
                    "expiry_time": expiry_time,
                    "max_renewals": self.get_max_renewals(attr_name),
                    "current_renewals": 0,
                }

                # 동적 속성을 S에 추가하여 복호화에 사용 가능하게 만들기
                attr_sanitized = self._sanitize_attribute(attr_value)
                if "S" in key and attr_sanitized not in key["S"]:
                    key["S"].append(attr_sanitized)

                # attr_mapping에도 추가
                if "attr_mapping" not in key:
                    key["attr_mapping"] = {}
                key["attr_mapping"][attr_name] = attr_sanitized

            # 키 업데이트 이력 추가
            key["update_history"] = []

            # 정적 속성도 dynamic_attributes에 추가 (조회용)
            for attr_name in base_attributes:
                key["dynamic_attributes"][attr_name] = attr_name

        return key

    def keygen(self, attributes):
        """기본 키 생성 메서드 오버라이드 - 추가 메타데이터 포함"""
        key = super().keygen(attributes)

        # 기본 키에 필요한 메타데이터 추가
        if isinstance(key, dict):
            # 동적 속성 메타데이터 추가
            key["dynamic_attributes"] = {attr: attr for attr in attributes}
            # 빈 만료 정보 추가
            key["expiry_info"] = {}
            # 발급 시간 추가
            key["issue_time"] = time.time()

        return key

    def check_key_validity(self, key):
        """
        키의 유효성 검사 (동적 속성의 만료 여부 확인)
        """
        if not isinstance(key, dict) or "dynamic_attributes" not in key:
            return {"valid": False, "reason": "유효하지 않은 키 형식"}

        current_time = time.time()
        valid_attrs = []
        expired_attrs = []

        # 동적 속성 유효성 검사
        for attr_name, attr_value in key["dynamic_attributes"].items():
            # subscription 또는 warranty인 경우만 만료 여부 검사
            if attr_name in ["subscription", "warranty"]:
                # 현재 예상 값 계산
                expected_value = self.compute_attribute_value(attr_name)

                # 값이 일치하면 유효
                if attr_value == expected_value:
                    valid_attrs.append(attr_name)
                else:
                    expired_attrs.append(attr_name)
            else:
                # 동적 속성이 아닌 경우는 항상 유효
                valid_attrs.append(attr_name)

        # 모든 필수 속성이 유효해야 키도 유효
        is_valid = len(expired_attrs) == 0

        return {
            "valid": is_valid,
            "valid_attrs": valid_attrs,
            "expired_attrs": expired_attrs,
        }

    def update_attribute(self, user_id, attribute_name):
        """특정 속성 갱신"""
        if attribute_name not in self.fading_functions:
            raise ValueError(f"동적 속성이 아닙니다: {attribute_name}")

        # 속성의 새 값 계산
        new_value = self.compute_attribute_value(attribute_name)

        # 새 키 컴포넌트 생성
        new_attr_key = self.cpabe.keygen(self.pk, self.mk, [attribute_name])

        # 갱신 정보 반환
        return {
            "attribute_name": attribute_name,
            "attribute_value": new_value,
            "attribute_key": new_attr_key,
            "issue_time": time.time(),
        }

    def merge_attribute_to_key(self, key, new_attr):
        """
        기존 키에 새 속성 병합 (부분 키 갱신)
        """
        if not isinstance(key, dict) or "dynamic_attributes" not in key:
            raise ValueError("유효하지 않은 키 형식")

        if not isinstance(new_attr, dict) or "attribute_name" not in new_attr:
            raise ValueError("유효하지 않은 속성 형식")

        # 새 키 객체 생성 (깊은 복사)
        updated_key = dict(key)

        # 복잡한 객체는 참조 복사 (charm-crypto Element 객체 등)
        for k, v in key.items():
            if k not in [
                "dynamic_attributes",
                "expiry_info",
                "update_history",
                "S",
                "attr_mapping",
            ]:
                updated_key[k] = v

        # 동적 속성 및 만료 정보 복사
        updated_key["dynamic_attributes"] = dict(key["dynamic_attributes"])
        if "expiry_info" in key:
            updated_key["expiry_info"] = dict(key["expiry_info"])
        else:
            updated_key["expiry_info"] = {}

        # 업데이트 이력 복사 및 추가
        if "update_history" in key:
            updated_key["update_history"] = list(key["update_history"])
        else:
            updated_key["update_history"] = []

        # 새 속성 정보 추가
        attr_name = new_attr["attribute_name"]
        attr_value = new_attr["attribute_value"]

        # 속성 값 업데이트
        updated_key["dynamic_attributes"][attr_name] = attr_value

        # attr_mapping 복사 및 업데이트
        if "attr_mapping" in key:
            updated_key["attr_mapping"] = dict(key["attr_mapping"])
        else:
            updated_key["attr_mapping"] = {}

        # 새 동적 속성을 attr_mapping에 추가
        sanitized_attr = self._sanitize_attribute(attr_value)
        updated_key["attr_mapping"][attr_name] = sanitized_attr

        # S 목록 업데이트 (매우 중요 - 이 값이 제대로 설정되어야 복호화가 작동함)
        if "S" in key:
            updated_key["S"] = list(key["S"])
            if sanitized_attr not in updated_key["S"]:
                updated_key["S"].append(sanitized_attr)

        # 처음 키 생성 시에도 동적 속성이 S에 포함되도록 설정
        if hasattr(self.cpabe, "unpack_attributes"):
            # 키에 동적 속성들도 추가
            if "Dj" in updated_key:
                updated_key["Dj"][sanitized_attr] = self.group.init(G1, 1)
            if "Djp" in updated_key:
                updated_key["Djp"][sanitized_attr] = self.group.init(G1, 1)

        # 만료 정보 업데이트
        if "expiry_info" in new_attr and attr_name in new_attr["expiry_info"]:
            updated_key["expiry_info"][attr_name] = new_attr["expiry_info"][attr_name]

        # 갱신 횟수 증가
        if attr_name in updated_key["expiry_info"]:
            current_renewals = updated_key["expiry_info"][attr_name].get(
                "current_renewals", 0
            )
            updated_key["expiry_info"][attr_name]["current_renewals"] = (
                current_renewals + 1
            )

        # 업데이트 이력에 기록
        updated_key["update_history"].append(
            {
                "attribute": attr_name,
                "value": attr_value,
                "update_time": time.time(),
            }
        )

        return updated_key

    def encrypt_with_dynamic_attributes(self, msg, policy_attributes):
        """
        동적 속성을 고려하여 메시지 암호화
        """
        # 빈 정책인 경우 처리
        if not policy_attributes:
            raise ValueError("정책 속성이 비어 있습니다")

        # 정책 속성 목록 처리
        if isinstance(policy_attributes, list):
            # 속성 목록 직접 처리 - 동적 속성 현재값 계산
            transformed_policy = []
            for attr_name in policy_attributes:
                if attr_name in ["subscription", "warranty"]:
                    # 동적 속성인 경우 현재 값 계산
                    attr_value = self.compute_attribute_value(attr_name)
                    transformed_policy.append(attr_value)
                else:
                    # 정적 속성은 그대로 사용
                    transformed_policy.append(attr_name)

            print(f"실제 사용 정책: {transformed_policy}")

            # 암호화 수행 - IoTCPABE의 encrypt 메서드 사용
            try:
                result = self.encrypt(msg, transformed_policy)
                return result
            except Exception as e:
                print(f"암호화 오류: {str(e)}")
                return None
        else:
            # 정책이 문자열이나 다른 형태인 경우
            try:
                result = self.encrypt(msg, policy_attributes)
                return result
            except Exception as e:
                print(f"암호화 오류: {str(e)}")
                return None

    def decrypt(self, ciphertext, key):
        """
        암호문 복호화 - 동적 속성 관리 개선
        """
        # dynamic_attributes에서 실제 속성값 적용
        if isinstance(key, dict) and "dynamic_attributes" in key and "S" in key:
            # 동적 속성을 속성 목록에 추가 (아직 추가되지 않은 경우)
            attr_mapping = key.get("attr_mapping", {})
            dynamic_attrs = key["dynamic_attributes"]

            # 키 유효성 검사
            validity = self.check_key_validity(key)
            if not validity["valid"]:
                print(f"키 유효성 검사 실패: {validity['expired_attrs']}")
                # 만료된 속성이 있다면 복호화 불가
                if validity["expired_attrs"]:
                    return False

        # 부모 클래스의 복호화 메서드 호출
        return super().decrypt(ciphertext, key)

    def get_attribute_expiry_time(self, attr_name):
        """
        속성의 만료 시간을 계산하여 반환
        """
        # 속성에 대한 페이딩 함수가 있는지 확인
        if attr_name in self.fading_functions:
            fading_func = self.fading_functions[attr_name]

            # 현재 시간 기준으로 다음 값 변경 시간 계산
            current_time = time.time()

            # 페이딩 함수에 따라 적절한 수명 속성 사용
            if hasattr(fading_func, "lifetime"):
                lifetime = fading_func.lifetime
            elif hasattr(fading_func, "period"):
                lifetime = fading_func.period
            else:
                # 기본 수명 (1시간)
                lifetime = 3600

            # 만료 시간 = 현재 시간 + 속성 수명
            return current_time + lifetime

        # 페이딩 함수가 없는 경우 매우 먼 미래 시간 반환 (실질적으로 만료되지 않음)
        return time.time() + (365 * 24 * 60 * 60)  # 1년 후

    def get_max_renewals(self, attr_name):
        """
        속성의 최대 갱신 횟수 반환
        """
        # 속성에 대한 페이딩 함수가 있는지 확인
        if attr_name in self.fading_functions:
            fading_func = self.fading_functions[attr_name]

            # HardExpiryFadingFunction은 max_renewals 속성을 갖고 있음
            if hasattr(fading_func, "max_renewals"):
                return fading_func.max_renewals

        # 기본값은 무제한 갱신 (-1)
        return -1
