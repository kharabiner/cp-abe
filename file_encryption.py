from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.key_authority import KeyAuthority
from cp_abe.fading_functions import LinearFadingFunction
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import os
import base64
import json
import time
import pickle  # 추가: 복잡한 객체 직렬화용


class CPABEFileEncryption:
    """
    CP-ABE 기반 파일 암호화/복호화 클래스
    하이브리드 암호화 사용:
    - 파일은 AES로 암호화
    - AES 키는 CP-ABE로 암호화
    """

    def __init__(self):
        # CP-ABE 시스템 초기화
        self.cpabe = DynamicCPABE()
        self.cpabe.setup()

        # 키 관리 기관 초기화
        self.authority = KeyAuthority(self.cpabe)

        # AES 설정
        self.aes_block_size = 16  # AES-128

    def setup_fading_functions(self, subscription_lifetime=86400):
        """구독 속성에 페이딩 함수 등록 (기본 1일)"""
        subscription_function = LinearFadingFunction(
            "subscription", subscription_lifetime
        )
        self.cpabe.register_fading_function("subscription", subscription_function)

    def register_device(self, device_id, attributes, subscription_days=30):
        """기기 등록 및 키 발급"""
        return self.authority.register_device(device_id, attributes, subscription_days)

    def encrypt_file(self, input_file, output_file, policy_attributes):
        """
        CP-ABE 정책 기반으로 파일 암호화
        """
        print(f"\n파일 암호화 시작: {input_file}")
        print(f"적용 정책: {' AND '.join(policy_attributes)}")

        # 파일 읽기
        with open(input_file, "rb") as f:
            file_data = f.read()

        # 1. 임의의 AES 키 생성 (32바이트 = AES-256)
        aes_key = get_random_bytes(32)
        print(f"AES 키 생성: {len(aes_key)*8}비트")

        # 2. AES로 파일 암호화
        iv = get_random_bytes(self.aes_block_size)
        cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, self.aes_block_size)
        encrypted_file_data = iv + cipher.encrypt(padded_data)
        print(
            f"AES로 파일 암호화 완료: {len(file_data)}바이트 -> {len(encrypted_file_data)}바이트"
        )

        # 3. AES 키를 CP-ABE로 암호화
        encrypted_aes_key_str = self.cpabe.encrypt_with_dynamic_attributes(
            base64.b64encode(aes_key).decode("utf-8"), policy_attributes
        )

        # charm-crypto Element를 직렬화 가능한 형식으로 변환
        # pickle 대신 charm-crypto 객체의 속성을 추출하여 직접 직렬화
        serialized_key = {}
        if isinstance(encrypted_aes_key_str, dict):
            for k, v in encrypted_aes_key_str.items():
                if hasattr(v, "serialize"):
                    # Element 객체인 경우 serialize() 메서드 사용
                    serialized_key[k] = base64.b64encode(v.serialize()).decode("utf-8")
                elif k == "policy" and isinstance(v, str):
                    # 정책 문자열은 그대로 저장
                    serialized_key[k] = v
                elif isinstance(v, dict):
                    # 중첩 딕셔너리 처리
                    serialized_key[k] = {}
                    for sub_k, sub_v in v.items():
                        if hasattr(sub_v, "serialize"):
                            serialized_key[k][sub_k] = base64.b64encode(
                                sub_v.serialize()
                            ).decode("utf-8")
                        else:
                            serialized_key[k][sub_k] = str(sub_v)
                else:
                    # 그 외 타입은 문자열 변환
                    serialized_key[k] = str(v)
        else:
            serialized_key = str(encrypted_aes_key_str)

        # 4. 메타데이터 생성
        metadata = {
            "version": "1.0",
            "encryption_type": "CP-ABE-AES-Hybrid",
            "policy": " AND ".join(policy_attributes),
            "encryption_date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "original_size": len(file_data),
        }

        # 5. 최종 암호화 패키지 구성
        package = {
            "metadata": metadata,
            "encrypted_key": serialized_key,
            "encrypted_file": base64.b64encode(encrypted_file_data).decode("utf-8"),
        }

        # 6. 파일로 저장
        with open(output_file, "w") as f:
            json.dump(package, f)

        print(f"암호화 완료. 출력 파일: {output_file}")
        print(f"파일은 '{metadata['policy']}' 정책으로 보호되었습니다.")

        return output_file

    def decrypt_file(self, encrypted_file, output_file, device_key):
        """
        CP-ABE 키를 사용하여 파일 복호화
        """
        print(f"\n파일 복호화 시도: {encrypted_file}")

        try:
            # 1. 암호화된 패키지 로드
            with open(encrypted_file, "r") as f:
                package = json.load(f)

            metadata = package["metadata"]
            serialized_key = package["encrypted_key"]
            encrypted_file_data = base64.b64decode(package["encrypted_file"])

            print(
                f"메타데이터: {metadata['encryption_type']}, 정책: {metadata['policy']}"
            )

            # 2. 키 유효성 검사
            validity = self.cpabe.check_key_validity(device_key)
            if not validity["valid"]:
                print(
                    f"오류: 키가 만료되었습니다. 만료된 속성: {validity['expired_attrs']}"
                )
                return False

            # 3. CP-ABE로 AES 키 복호화
            try:
                # 직렬화된 CP-ABE 암호문을 직접 복호화 (복구 과정 필요 없음)
                # 이 부분은 단순화를 위해 암호문을 문자열 형태로 처리
                decrypted_key_base64 = self.cpabe.decrypt(serialized_key, device_key)
                aes_key = base64.b64decode(decrypted_key_base64)
                print("CP-ABE 키 복호화 성공: AES 키 복구됨")
            except Exception as e:
                print(f"CP-ABE 키 복호화 실패: {str(e)}")
                print("정책 조건을 충족하지 않거나 키가 만료되었습니다.")
                return False

            # 4. AES로 파일 복호화
            iv = encrypted_file_data[: self.aes_block_size]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(
                encrypted_file_data[self.aes_block_size :]
            )

            # 패딩 제거
            decrypted_data = unpad(decrypted_padded, self.aes_block_size)

            # 5. 복호화된 파일 저장
            with open(output_file, "wb") as f:
                f.write(decrypted_data)

            print(f"복호화 성공. 출력 파일: {output_file}")
            print(
                f"원본 크기: {metadata['original_size']}바이트, 복구된 크기: {len(decrypted_data)}바이트"
            )

            return True

        except Exception as e:
            print(f"파일 복호화 중 오류 발생: {str(e)}")
            import traceback

            traceback.print_exc()
            return False

    def renew_subscription(self, device_id):
        """
        기기의 구독 속성 갱신
        """
        result = self.authority.request_attribute_renewal(device_id, "subscription")
        return result


def demo_file_encryption():
    """
    CP-ABE 파일 암호화 데모
    """
    print("\n===== CP-ABE 파일 암호화 데모 =====")

    # 암호화 시스템 초기화
    encryptor = CPABEFileEncryption()

    # 구독 속성 페이딩 함수 설정 (테스트를 위해 짧게 5초로 설정)
    encryptor.setup_fading_functions(subscription_lifetime=5)

    # 기기 등록 (K5 차량)
    device_id = "K5-2023-54321"
    attributes = ["model", "premium"]  # 초기 속성 (구독 속성은 자동 추가)
    device_key = encryptor.register_device(device_id, attributes)
    print(f"기기 등록 완료: {device_id}")

    # 테스트 파일 생성
    test_file = "test_message.txt"
    with open(test_file, "w") as f:
        f.write("이것은 중요한 기밀 정보입니다. CP-ABE로 보호됩니다.")

    # 파일 암호화 (두 가지 다른 정책)
    basic_encrypted = "basic_encrypted.cpabe"
    premium_encrypted = "premium_encrypted.cpabe"

    # 기본 파일은 모델 속성만 필요
    encryptor.encrypt_file(test_file, basic_encrypted, ["model"])

    # 프리미엄 파일은 모델+구독 속성 필요
    encryptor.encrypt_file(test_file, premium_encrypted, ["model", "subscription"])

    # 초기 복호화 테스트
    print("\n[1단계] 초기 복호화 테스트:")
    basic_decrypted = "basic_decrypted.txt"
    premium_decrypted = "premium_decrypted.txt"

    print("\n기본 파일 복호화 시도:")
    encryptor.decrypt_file(basic_encrypted, basic_decrypted, device_key)

    print("\n프리미엄 파일 복호화 시도:")
    encryptor.decrypt_file(premium_encrypted, premium_decrypted, device_key)

    # 구독 만료 대기
    print("\n[2단계] 구독 만료 대기 (7초):")
    print("잠시 기다리는 중...")
    time.sleep(7)

    # 만료 후 복호화 테스트
    print("\n[3단계] 구독 만료 후 복호화 테스트:")
    basic_decrypted2 = "basic_decrypted_after_expiry.txt"
    premium_decrypted2 = "premium_decrypted_after_expiry.txt"

    print("\n구독 만료 확인:")
    validity = encryptor.cpabe.check_key_validity(device_key)
    print(f"키 유효함: {validity['valid']}")
    print(f"만료된 속성: {validity['expired_attrs']}")

    print("\n기본 파일 복호화 시도 (성공 예상):")
    encryptor.decrypt_file(basic_encrypted, basic_decrypted2, device_key)

    print("\n프리미엄 파일 복호화 시도 (실패 예상):")
    result = encryptor.decrypt_file(premium_encrypted, premium_decrypted2, device_key)
    if not result:
        print("예상대로 실패: 구독이 필요한 파일에 접근할 수 없습니다.")

    # 구독 갱신
    print("\n[4단계] 구독 갱신:")
    print("갱신 요청 중...")
    renewal_result = encryptor.renew_subscription(device_id)

    if renewal_result["success"]:
        new_attr = renewal_result["attribute"]
        print(f"갱신 성공. 새 속성 값: {new_attr['attribute_value']}")

        # 키 갱신
        device_key = encryptor.cpabe.merge_attribute_to_key(device_key, new_attr)
        print("기기 키 갱신 완료")

        # 갱신 후 복호화 재시도
        print("\n[5단계] 키 갱신 후 복호화 재시도:")
        premium_decrypted3 = "premium_decrypted_after_renewal.txt"

        print("\n프리미엄 파일 복호화 시도 (성공 예상):")
        encryptor.decrypt_file(premium_encrypted, premium_decrypted3, device_key)
    else:
        print(f"갱신 실패: {renewal_result['reason']}")


if __name__ == "__main__":
    demo_file_encryption()
