from datetime import datetime
from .iot_cpabe import IoTCPABE


class FadingCPABE(IoTCPABE):
    def __init__(self):
        super().__init__()

    def keygen_with_expiry(self, attributes, expiry_attributes):
        """
        Generate a key with expiry attributes
        """
        # 기본 속성 설정
        all_attributes = attributes.copy()

        # 만료 속성 추가 (속성에 만료일 포함)
        # 속성 이름에 콜론(:)을 사용하지 않도록 수정
        for attr, expiry in expiry_attributes.items():
            # 만료일을 timestamp로 변환
            expiry_timestamp = int(datetime.strptime(expiry, "%Y-%m-%d").timestamp())
            # 속성 형식 단순화
            all_attributes.append(f"{attr}")  # 만료 속성 이름만 추가

            # 만료일 정보 별도 저장
            if not isinstance(all_attributes, list):
                all_attributes = list(all_attributes)

        # 키 생성
        key = self.cpabe.keygen(self.pk, self.mk, all_attributes)

        # 키에 만료일 정보 저장
        if isinstance(key, dict):
            key["orig_attributes"] = all_attributes
            # 만료 정보 추가 저장
            key["expiry_info"] = {
                attr: int(datetime.strptime(expiry, "%Y-%m-%d").timestamp())
                for attr, expiry in expiry_attributes.items()
            }

        return key

    def partial_key_update(self, old_key, new_expiry_attributes):
        """
        Update only the expiry attributes of a key

        Args:
            old_key: The old key
            new_expiry_attributes: Dictionary of attributes with new expiry dates {attr: new_expiry_date}
        """
        # 이전 키의 속성을 가져옴
        current_attributes = []
        expiry_attrs_to_update = {}

        # 키 객체에서 속성 리스트 가져오기
        if isinstance(old_key, dict) and "orig_attributes" in old_key:
            attr_list = old_key["orig_attributes"]
        elif isinstance(old_key, dict) and "attr_list" in old_key:
            attr_list = old_key["attr_list"]
        else:
            # 속성 리스트가 없는 경우 기본 속성만 사용
            attr_list = []
            print("경고: 키에 속성 리스트가 없습니다. 기본 속성만 유지됩니다.")

        for attr in attr_list:
            if ":" in attr:  # 만료 날짜가 있는 속성
                attr_name, expiry_timestamp = attr.split(":")
                if attr_name in new_expiry_attributes:
                    # 업데이트할 속성
                    expiry_attrs_to_update[attr_name] = new_expiry_attributes[attr_name]
                else:
                    # 그대로 유지할 속성
                    current_attributes.append(attr)
            else:
                # 일반 속성은 그대로 유지
                current_attributes.append(attr)

        # 새 키 생성
        return self.keygen_with_expiry(current_attributes, expiry_attrs_to_update)

    def check_key_validity(self, key):
        """
        Check if the key's expiry attributes are still valid
        """
        now = int(datetime.now().timestamp())
        valid_attrs = []
        expired_attrs = []

        # 키에 직접 저장된 만료 정보 확인
        if isinstance(key, dict) and "expiry_info" in key:
            for attr, expiry_timestamp in key["expiry_info"].items():
                if expiry_timestamp > now:
                    valid_attrs.append(attr)
                else:
                    expired_attrs.append(attr)

            return {
                "valid": len(expired_attrs) == 0,
                "valid_attrs": valid_attrs,
                "expired_attrs": expired_attrs,
            }

        # 기존 방식으로 검사 (하위 호환성)
        # 키 객체에서 속성 리스트 가져오기
        if isinstance(key, dict) and "orig_attributes" in key:
            attr_list = key["orig_attributes"]
        elif isinstance(key, dict) and "attr_list" in key:
            attr_list = key["attr_list"]
        else:
            # 속성 리스트가 없는 경우 키가 항상 유효하다고 가정
            print("경고: 키에 속성 리스트가 없습니다. 키를 항상 유효하다고 가정합니다.")
            return {"valid": True, "valid_attrs": [], "expired_attrs": []}

        for attr in attr_list:
            if ":" in attr:  # 만료 날짜가 있는 속성
                attr_name, expiry_timestamp = attr.split(":")
                if int(expiry_timestamp) > now:
                    valid_attrs.append(attr)
                else:
                    expired_attrs.append(attr_name)
            else:
                valid_attrs.append(attr)

        return {
            "valid": len(expired_attrs) == 0,
            "valid_attrs": valid_attrs,
            "expired_attrs": expired_attrs,
        }

    def encrypt_update_package(self, update_data, policy):
        """
        Encrypt an update package with the given policy
        """
        # 정책 단순화
        return self.encrypt(update_data, policy)
