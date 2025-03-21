from .dynamic_cpabe import DynamicCPABE
from datetime import datetime, timedelta
import time
import uuid
import logging


class KeyAuthority:
    """
    키 관리 기관(Key Authority) 클래스
    - 속성 갱신 정책 관리
    - 갱신 요청 승인 또는 거부
    - 부분 키 갱신 수행
    """

    def __init__(self, cpabe_system=None):
        if cpabe_system is None:
            self.cpabe = DynamicCPABE()
            self.cpabe.setup()
        else:
            self.cpabe = cpabe_system

        self.renewal_policies = {}  # 갱신 정책
        self.renewal_history = {}  # 갱신 이력
        self.device_registry = {}  # 기기 등록 정보

    def register_device(
        self, device_id, initial_attributes, subscription_period_days=30
    ):
        """
        새 IoT 기기 등록 및 초기 키 발급
        """
        # 구독 속성 추가 (만료일 설정)
        now = datetime.now()
        expiry_date = (now + timedelta(days=subscription_period_days)).strftime(
            "%Y-%m-%d"
        )

        # 사용자 ID 생성
        user_id = self.cpabe.create_user_record(device_id)

        # DynamicCPABE에 맞는 방식으로 키 생성
        if hasattr(self.cpabe, "keygen_with_dynamic_attributes"):
            # DynamicCPABE 클래스의 경우
            key = self.cpabe.keygen_with_dynamic_attributes(user_id, initial_attributes)
        else:
            # FadingCPABE 클래스의 경우
            # 기본 속성과 만료 속성 분리
            regular_attrs = [
                attr for attr in initial_attributes if attr != "subscription"
            ]
            expiry_attrs = {"subscription": expiry_date}
            key = self.cpabe.keygen_with_expiry(regular_attrs, expiry_attrs)

            # 키에 dynamic_attributes 필드 추가 (병합 작업 지원을 위함)
            if isinstance(key, dict) and "dynamic_attributes" not in key:
                key["dynamic_attributes"] = {}
                for attr in initial_attributes:
                    if attr == "subscription":
                        key["dynamic_attributes"][attr] = f"subscription_0"  # 초기값
                    else:
                        key["dynamic_attributes"][attr] = f"{attr}_0"  # 초기값

        # 기기 등록 정보 저장
        self.device_registry[device_id] = {
            "user_id": user_id,
            "registration_date": now.isoformat(),
            "subscription_end": expiry_date,
            "attributes": initial_attributes,
            "renewal_count": 0,
            "status": "active",
        }

        print(f"기기 {device_id} 등록 완료. 구독 만료일: {expiry_date}")
        return key

    def set_renewal_policy(
        self,
        attribute_name,
        max_renewals=None,
        renewal_period_days=None,
        allowed_devices=None,
        blacklisted_devices=None,
    ):
        """
        속성별 갱신 정책 설정
        """
        self.renewal_policies[attribute_name] = {
            "max_renewals": max_renewals,  # None = 무제한
            "renewal_period_days": renewal_period_days,  # None = 기본값
            "allowed_devices": allowed_devices,  # None = 모든 기기 허용
            "blacklisted_devices": blacklisted_devices or [],  # 차단된 기기 목록
        }
        print(f"{attribute_name} 속성에 대한 갱신 정책 설정 완료")

    def request_attribute_renewal(self, device_id, attribute_name):
        """
        속성 갱신 요청 처리 - IoT 기기가 호출
        """
        print(f"\n기기 {device_id}로부터 '{attribute_name}' 속성 갱신 요청 수신")

        # 1. 기기가 등록되어 있는지 확인
        if device_id not in self.device_registry:
            print(f"오류: 등록되지 않은 기기 {device_id}")
            return {"success": False, "reason": "unregistered_device"}

        device_info = self.device_registry[device_id]
        user_id = device_info["user_id"]

        # 2. 갱신 정책 확인
        policy = self.renewal_policies.get(attribute_name, {})

        # 속성 갱신 횟수 추적
        renewal_key = f"{device_id}_{attribute_name}"
        if renewal_key not in self.renewal_history:
            self.renewal_history[renewal_key] = []

        current_renewals = len(self.renewal_history[renewal_key])

        # 3. 정책에 따른 갱신 가능 여부 결정

        # 3.1. 최대 갱신 횟수 확인
        max_renewals = policy.get("max_renewals")
        if max_renewals is not None and current_renewals >= max_renewals:
            print(f"갱신 거부: 최대 갱신 횟수({max_renewals}회) 초과")
            return {"success": False, "reason": "max_renewals_exceeded"}

        # 3.2. 블랙리스트 확인
        if device_id in policy.get("blacklisted_devices", []):
            print(f"갱신 거부: 기기 {device_id}가 블랙리스트에 포함됨")
            return {"success": False, "reason": "device_blacklisted"}

        # 3.3. 허용 기기 리스트 확인
        allowed_devices = policy.get("allowed_devices")
        if allowed_devices is not None and device_id not in allowed_devices:
            print(f"갱신 거부: 기기 {device_id}가 허용 목록에 없음")
            return {"success": False, "reason": "device_not_allowed"}

        # 4. 갱신 승인 및 새 속성 발급
        print(f"갱신 승인: 기기 {device_id}의 {attribute_name} 속성")

        # 4.1. 갱신 기간 결정 (기본값 또는 정책 기반)
        renewal_days = policy.get("renewal_period_days", 30)  # 기본값 30일

        # 4.2. 새 만료일 계산
        if attribute_name == "subscription":
            now = datetime.now()
            new_expiry = (now + timedelta(days=renewal_days)).strftime("%Y-%m-%d")

            # 4.3. 속성 갱신
            new_attr = self.cpabe.update_attribute(user_id, attribute_name)

            # 4.4. 기기 정보 업데이트
            device_info["subscription_end"] = new_expiry
            device_info["renewal_count"] += 1

            # 4.5. 갱신 이력 기록
            self.renewal_history[renewal_key].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "new_expiry": new_expiry,
                    "new_value": new_attr["attribute_value"],
                }
            )

            print(f"속성 갱신 완료. 새 만료일: {new_expiry}")
            return {
                "success": True,
                "attribute": new_attr,
                "expiry_date": new_expiry,
                "renewal_count": current_renewals + 1,
            }
        else:
            # 구독 외 다른 속성 갱신 로직
            new_attr = self.cpabe.update_attribute(user_id, attribute_name)
            self.renewal_history[renewal_key].append(
                {
                    "timestamp": datetime.now().isoformat(),
                    "new_value": new_attr["attribute_value"],
                }
            )
            return {"success": True, "attribute": new_attr}

    def get_device_info(self, device_id):
        """
        기기 정보 조회
        """
        if device_id not in self.device_registry:
            return None

        return self.device_registry[device_id]

    def revoke_device(self, device_id, reason=None):
        """
        기기 접근 권한 취소
        """
        if device_id not in self.device_registry:
            print(f"오류: 등록되지 않은 기기 {device_id}")
            return False

        # 기기 상태를 'revoked'로 변경
        self.device_registry[device_id]["status"] = "revoked"
        self.device_registry[device_id]["revocation_reason"] = reason
        self.device_registry[device_id]["revocation_date"] = datetime.now().isoformat()

        # 블랙리스트에 추가
        for attr_name, policy in self.renewal_policies.items():
            if "blacklisted_devices" not in policy:
                policy["blacklisted_devices"] = []
            if device_id not in policy["blacklisted_devices"]:
                policy["blacklisted_devices"].append(device_id)

        print(f"기기 {device_id}의 접근 권한이 취소됨. 사유: {reason}")
        return True
