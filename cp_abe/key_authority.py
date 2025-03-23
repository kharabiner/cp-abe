from .dynamic_cpabe import DynamicCPABE
from datetime import datetime, timedelta
import time
import uuid
import logging
import hashlib


class KeyAuthority:
    """
    키 관리 기관(Key Authority) 클래스 - 시간 제한 속성만으로 접근 제한

    이 클래스는 다음과 같은 개선 사항을 포함합니다:
    - 취소 메커니즘 제거 (기기 취소 상황 불필요)
    - 시간 기반 속성으로 접근 자동 제한
    - 갱신 거부를 통한 간접적 접근 관리
    """

    def __init__(self, cpabe_system=None):
        if cpabe_system is None:
            self.cpabe = DynamicCPABE()
            self.cpabe.setup()
        else:
            self.cpabe = cpabe_system

        # 갱신 정책 관리
        self.renewal_policies = {}

        # 기기 관리 (취소 없이 상태만 관리)
        self.device_status = {}  # 기기 상태 정보 (활성/비활성)
        self._secure_storage = {}  # 기기 최소 정보 저장

        # 로깅 설정
        self.logger = logging.getLogger("KeyAuthority")
        self.logger.setLevel(logging.INFO)

    def _create_device_hash(self, device_id):
        """기기 ID에 대한 해시 생성 (식별용)"""
        return hashlib.sha256(device_id.encode()).hexdigest()[:16]

    def _get_minimal_device_info(self, device_id):
        """필요한 최소 정보만 조회"""
        device_hash = self._create_device_hash(device_id)

        # 안전한 스토리지에서 최소 정보만 조회
        if device_hash in self._secure_storage:
            return self._secure_storage[device_hash]

        return None

    def register_device(
        self, device_id, initial_attributes, subscription_period_days=30
    ):
        """기기 등록 - 시간 제한 속성 포함"""
        # 사용자 ID 생성
        user_id = self.cpabe.create_user_record(device_id)

        # 구독 속성 자동 추가
        complete_attributes = list(initial_attributes)
        if "subscription" not in complete_attributes:
            complete_attributes.append("subscription")

        # 키 생성
        key = self.cpabe.keygen_with_dynamic_attributes(user_id, complete_attributes)

        # 기기 해시 생성
        device_hash = self._create_device_hash(device_id)

        # 최소 정보만 저장
        now = datetime.now()
        expiry_date = (now + timedelta(days=subscription_period_days)).strftime(
            "%Y-%m-%d"
        )

        self._secure_storage[device_hash] = {
            "user_id": user_id,
            "subscription_end": expiry_date,
            "registration_date": now.isoformat(),
            "status": "active" if subscription_period_days > 0 else "inactive",
        }

        # 상태 정보 업데이트
        self.device_status[device_id] = (
            "active" if subscription_period_days > 0 else "inactive"
        )

        self.logger.info(f"기기 {device_id} 등록 완료. 구독 만료일: {expiry_date}")
        return key

    def set_renewal_policy(self, attribute_name, **policy_params):
        """속성별 갱신 정책 설정"""
        self.renewal_policies[attribute_name] = policy_params
        self.logger.info(f"{attribute_name} 속성에 대한 갱신 정책 설정 완료")

        # 정책 세부 내용 로깅
        for param, value in policy_params.items():
            self.logger.debug(f"- {param}: {value}")

    def request_attribute_renewal(self, device_id, attribute_name):
        """속성 갱신 요청 처리 - 갱신 조건 충족 여부에 따라 허용/거부"""
        self.logger.info(
            f"기기 {device_id}로부터 '{attribute_name}' 속성 갱신 요청 수신"
        )

        # 1. 기기 정보 최소한으로 조회
        device_info = self._get_minimal_device_info(device_id)
        if not device_info:
            return {"success": False, "reason": "unregistered_device"}

        user_id = device_info["user_id"]

        # 2. 갱신 정책 확인
        policy = self.renewal_policies.get(attribute_name, {})

        # 2.1. 기기 상태 확인 - 비활성 기기는 갱신 불가
        if device_info.get("status") == "inactive":
            self.logger.info(f"기기 {device_id}는 비활성 상태로 갱신 거부")
            return {"success": False, "reason": "inactive_device"}

        # 2.2. 허용 기기 리스트 확인 (명시적으로 허용된 기기만)
        allowed_devices = policy.get("allowed_devices")
        if allowed_devices is not None and device_id not in allowed_devices:
            return {"success": False, "reason": "device_not_allowed"}

        # 2.3. 갱신 횟수 제한 확인
        max_renewals = policy.get("max_renewals")
        current_renewals = device_info.get("renewal_count", {}).get(attribute_name, 0)

        if max_renewals is not None and current_renewals >= max_renewals:
            self.logger.info(
                f"기기 {device_id}의 {attribute_name} 속성 최대 갱신 횟수 초과"
            )
            return {"success": False, "reason": "max_renewals_reached"}

        # 3. 갱신 승인 및 새 속성 발급
        self.logger.info(f"갱신 승인: 기기 {device_id}의 {attribute_name} 속성")

        # 3.1. 갱신 기간 결정
        renewal_days = policy.get("renewal_period_days", 30)  # 기본값 30일

        # 3.2. 새 만료일 계산
        if attribute_name == "subscription":
            now = datetime.now()
            new_expiry = (now + timedelta(days=renewal_days)).strftime("%Y-%m-%d")

            # 기기 정보 최소한으로 업데이트
            device_hash = self._create_device_hash(device_id)
            if device_hash in self._secure_storage:
                self._secure_storage[device_hash]["subscription_end"] = new_expiry

                # 갱신 횟수 증가
                if "renewal_count" not in self._secure_storage[device_hash]:
                    self._secure_storage[device_hash]["renewal_count"] = {}

                if (
                    attribute_name
                    not in self._secure_storage[device_hash]["renewal_count"]
                ):
                    self._secure_storage[device_hash]["renewal_count"][
                        attribute_name
                    ] = 0

                self._secure_storage[device_hash]["renewal_count"][attribute_name] += 1

            # 3.3. 속성 갱신
            new_attr = self.cpabe.update_attribute(user_id, attribute_name)

            self.logger.info(f"속성 갱신 완료. 새 만료일: {new_expiry}")
            return {"success": True, "attribute": new_attr, "expiry_date": new_expiry}
        else:
            # 구독 외 다른 속성 갱신
            new_attr = self.cpabe.update_attribute(user_id, attribute_name)

            # 갱신 횟수 증가
            device_hash = self._create_device_hash(device_id)
            if device_hash in self._secure_storage:
                if "renewal_count" not in self._secure_storage[device_hash]:
                    self._secure_storage[device_hash]["renewal_count"] = {}

                if (
                    attribute_name
                    not in self._secure_storage[device_hash]["renewal_count"]
                ):
                    self._secure_storage[device_hash]["renewal_count"][
                        attribute_name
                    ] = 0

                self._secure_storage[device_hash]["renewal_count"][attribute_name] += 1

            return {"success": True, "attribute": new_attr}

    def get_device_info(self, device_id):
        """기기 정보 조회 - 최소 필요 정보만 반환"""
        device_hash = self._create_device_hash(device_id)
        if device_hash in self._secure_storage:
            # 민감 정보 제외하고 반환
            info = dict(self._secure_storage[device_hash])
            if "user_id" in info:
                del info["user_id"]  # 사용자 ID는 민감 정보이므로 제외
            return info
        return None

    def set_device_inactive(self, device_id, reason=None):
        """기기 비활성화 - 취소 대신 상태만 변경"""
        device_hash = self._create_device_hash(device_id)

        # 기기가 등록되어 있는지 확인
        if device_hash not in self._secure_storage:
            self.logger.warning(f"오류: 등록되지 않은 기기 {device_id}")
            return False

        # 상태 정보 업데이트
        self.device_status[device_id] = "inactive"

        # 최소 정보만 업데이트
        if device_hash in self._secure_storage:
            self._secure_storage[device_hash]["status"] = "inactive"
            self._secure_storage[device_hash]["inactive_reason"] = reason
            self._secure_storage[device_hash][
                "inactive_date"
            ] = datetime.now().isoformat()

        self.logger.info(f"기기 {device_id}가 비활성화됨. 사유: {reason}")
        self.logger.info(
            "참고: 비활성 기기는 갱신이 불가하며 시간 제한 속성이 만료됨에 따라 자동으로 접근이 제한됩니다."
        )

        return True
