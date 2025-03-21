from datetime import datetime
from .iot_cpabe import IoTCPABE


class FadingCPABE(IoTCPABE):
    def __init__(self):
        super().__init__()

    def keygen_with_expiry(self, attributes, expiry_attributes):
        """
        Generate a key with expiry attributes

        Args:
            attributes: Regular attributes
            expiry_attributes: Dictionary of attributes with expiry dates {attr: expiry_date}
        """
        # 기본 속성 설정
        all_attributes = attributes.copy()

        # 만료 속성 추가 (속성:만료일 형식)
        for attr, expiry in expiry_attributes.items():
            # 만료일을 timestamp로 변환하여 속성에 추가
            expiry_timestamp = int(datetime.strptime(expiry, "%Y-%m-%d").timestamp())
            all_attributes.append(f"{attr}:{expiry_timestamp}")

        # 키 생성
        return self.cpabe.keygen(self.pk, self.mk, all_attributes)

    def partial_key_update(self, old_key, new_expiry_attributes):
        """
        Update only the expiry attributes of a key

        Args:
            old_key: The old key
            new_expiry_attributes: Dictionary of attributes with new expiry dates {attr: new_expiry_date}
        """
        # 기존 키에서 만료되지 않은 속성 추출
        current_attributes = []
        expiry_attrs_to_update = {}

        for attr in old_key["attr_list"]:
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

        for attr in key["attr_list"]:
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
        return self.encrypt(update_data, policy)
