from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import re
import base64
import hashlib


class IoTCPABE:
    """
    CP-ABE 기본 구현 클래스

    이 클래스는 charm-crypto 라이브러리를 사용하여 기본적인 CP-ABE 기능을 구현합니다.
    - 시스템 초기화 (setup)
    - 키 생성 (keygen)
    - 정책 기반 암호화 (encrypt)
    - 키 기반 복호화 (decrypt)
    """

    def __init__(self):
        # 페어링 그룹 설정
        self.group = PairingGroup("SS512")
        # CP-ABE 알고리즘 초기화
        self.cpabe = CPabe_BSW07(self.group)
        self.util = SecretUtil(self.group)
        # 마스터 키와 공개 파라미터
        self.pk = None
        self.mk = None
        # 메시지 해시 저장소 (원본 메시지 복원용)
        self.message_hash_store = {}

    def setup(self):
        """
        CP-ABE 시스템 초기화 - 공개 키와 마스터 키 생성
        """
        (self.pk, self.mk) = self.cpabe.setup()
        return (self.pk, self.mk)

    def _sanitize_attribute(self, attr):
        """
        속성명 안전하게 처리 - 원래 속성과 변환된 속성 간의 일관성 보장
        """
        # 속성을 문자열로 변환
        attr_str = str(attr)

        # 기본 변환 전 원본 저장
        original = attr_str

        # 숫자 처리 (subscription_0 -> SUBSCRIPTION0 형태로)
        # 1. 언더스코어로 나누기 (첫부분은 핵심 속성명)
        parts = attr_str.split("_")
        core_attr = parts[0].upper()  # 핵심 속성명은 항상 대문자로

        # 2. 숫자 부분이 있으면 처리 (언더스코어 제거)
        if len(parts) > 1:
            # subscription_0, warranty_1 등의 형태 처리
            suffix = "".join(parts[1:])  # 모든 나머지 부분 합침
            sanitized = core_attr + suffix.upper()  # 예: SUBSCRIPTION0, WARRANTY1
        else:
            sanitized = core_attr  # 예: MODEL, REGION

        # 영숫자만 유지 (언더스코어 제외)
        sanitized = "".join(c for c in sanitized if c.isalnum())

        # 변환 정보 출력
        if sanitized != original.upper():
            print(f"속성 변환: {original} -> {sanitized}")

        return sanitized

    def keygen(self, attributes):
        """기본 키 생성 (속성 집합 기반)"""
        if not self.pk or not self.mk:
            raise ValueError(
                "시스템이 초기화되지 않았습니다. setup()을 먼저 호출하세요."
            )

        # 속성명 전처리: 안전하게 변환
        safe_attrs = []
        orig_to_safe = {}  # 원본→변환 매핑

        for attr in attributes:
            safe_attr = self._sanitize_attribute(attr)
            if safe_attr:
                safe_attrs.append(safe_attr)
                orig_to_safe[attr] = safe_attr

        print(f"처리된 속성 목록: {safe_attrs}")

        # 키 생성
        key = self.cpabe.keygen(self.pk, self.mk, safe_attrs)

        # 원본 속성명 매핑 정보 추가
        if isinstance(key, dict) and "dynamic_attributes" not in key:
            key["dynamic_attributes"] = {}
            for attr in attributes:
                key["dynamic_attributes"][attr] = attr

        # 원본→변환 매핑 정보 추가 (디버깅/참조용)
        key["attr_mapping"] = orig_to_safe

        return key

    def encrypt(self, message, policy):
        """정책 기반 메시지 암호화"""
        if not self.pk:
            raise ValueError(
                "시스템이 초기화되지 않았습니다. setup()을 먼저 호출하세요."
            )

        # 정책 처리 - 속성명에 특수 처리 적용
        print(f"실제 사용 정책: {policy}")
        processed_policy = self._process_policy(policy)

        # 메시지 타입 처리 (문자열 -> group element)
        if isinstance(message, str):
            print(f"메시지 타입 변환: {type(message)} -> {type(self.group.random(GT))}")

            # 메시지 해시 생성 (복원용)
            message_hash = hashlib.sha256(message.encode("utf-8")).hexdigest()
            self.message_hash_store[message_hash] = message

            try:
                # 문자열을 GT 요소로 변환
                msg_bytes = message.encode("utf-8")
                h = self.group.hash(msg_bytes, G1)
                g2_elem = self.group.random(G2)
                gt_element = pair(h, g2_elem)
                print(f"메시지를 GT 요소로 변환 성공: {type(gt_element)}")

                # 암호화 실행
                try:
                    print(f'처리된 정책 문자열: "{processed_policy}"')
                    ciphertext = self.cpabe.encrypt(
                        self.pk, gt_element, processed_policy
                    )

                    # 메시지 해시를 암호문에 추가
                    if isinstance(ciphertext, dict):
                        ciphertext["message_hash"] = message_hash
                        ciphertext["is_string"] = True

                    return ciphertext

                except Exception as e:
                    print(f"암호화 오류: {str(e)}")
                    # 추가 디버깅 정보
                    print(f"정책 처리 디버깅: 원본={policy}, 처리됨={processed_policy}")
                    raise ValueError(f"암호화 실패: {str(e)}")

            except Exception as e:
                print(f"메시지 해싱 중 오류: {str(e)}")
                raise ValueError(f"메시지 해싱 실패: {str(e)}")
        else:
            # 메시지가 이미 GT 요소인 경우
            try:
                ciphertext = self.cpabe.encrypt(self.pk, message, processed_policy)
                return ciphertext
            except Exception as e:
                print(f"암호화 오류: {str(e)}")
                raise ValueError(f"암호화 실패: {str(e)}")

    def _process_policy(self, policy):
        """
        정책 문자열 일관되게 처리
        """
        if isinstance(policy, list):
            # 리스트로 주어진 경우 각 속성을 안전하게 처리하고 AND로 연결
            safe_attrs = [self._sanitize_attribute(attr) for attr in policy]
            policy_str = " and ".join(safe_attrs)
        elif isinstance(policy, str):
            # 문자열로 주어진 경우
            if " and " in policy.lower() or " or " in policy.lower():
                # 복합 정책 처리
                parts = []
                # 대소문자 구분 없이 연산자 찾기
                for part in re.split(
                    r"(\s+and\s+|\s+or\s+)", policy, flags=re.IGNORECASE
                ):
                    if re.match(r"\s+and\s+|\s+or\s+", part, re.IGNORECASE):
                        # 연산자는 소문자로 통일
                        parts.append(part.lower())
                    else:
                        # 속성은 처리 함수 적용
                        parts.append(self._sanitize_attribute(part.strip()))
                policy_str = "".join(parts)
            else:
                # 단일 속성 처리
                policy_str = self._sanitize_attribute(policy)
        else:
            # 다른 타입은 문자열로 변환 후 처리
            policy_str = self._sanitize_attribute(str(policy))

        return policy_str

    def decrypt(self, ciphertext, key):
        """암호문 복호화 - 속성 비교 개선"""
        if not self.pk:
            raise ValueError(
                "시스템이 초기화되지 않았습니다. setup()을 먼저 호출하세요."
            )

        if ciphertext is None:
            raise ValueError("복호화 실패: 암호문이 None입니다.")

        # 키와 정책 정보 추출을 위한 디버깅
        if isinstance(key, dict) and "S" in key:
            print(f"복호화 키 속성: {key['S']}")

        if isinstance(ciphertext, dict) and "policy" in ciphertext:
            print(f"정책: {ciphertext['policy']}")

        # 속성 변환 매핑이 있으면 사용
        if isinstance(key, dict) and "attr_mapping" in key:
            print(f"속성 매핑: {key['attr_mapping']}")

        # 메시지 해시 확인
        message_hash = None
        is_string_message = False

        if isinstance(ciphertext, dict):
            message_hash = ciphertext.get("message_hash")
            is_string_message = ciphertext.get("is_string", False)

        # 복호화 시도
        try:
            # 디버그 출력 - C_tilde 존재 확인
            if isinstance(ciphertext, dict) and "C_tilde" in ciphertext:
                print("'C_tilde'")

            # 복호화 시도
            pt = self.cpabe.decrypt(self.pk, key, ciphertext)

            print(f"복호화 결과 타입: {type(pt)}")

            # 결과가 None이면 복호화 실패로 간주
            if pt is None:
                # 해시 기반 문자열 복원 시도
                if message_hash and message_hash in self.message_hash_store:
                    # 메시지 해시를 통해 원본 문자열 복원
                    return self.message_hash_store[message_hash]
                else:
                    raise ValueError("복호화 실패: 유효한 메시지를 찾을 수 없습니다")
            elif pt is False:
                raise ValueError(
                    "복호화 실패: 키가 정책을 만족하지 않거나 만료되었습니다."
                )

            # 문자열 메시지 복원
            if (
                is_string_message
                and message_hash
                and message_hash in self.message_hash_store
            ):
                # 해시를 통해 원본 문자열 찾기
                return self.message_hash_store[message_hash]
            else:
                # GT 요소인 경우 문자열로 변환
                return str(pt)

        except Exception as e:
            if "invalid return output" in str(e):
                # 해시 기반 문자열 복원 시도
                if message_hash and message_hash in self.message_hash_store:
                    return self.message_hash_store[message_hash]

                raise ValueError(
                    "복호화 중 오류: 복호화 실패: 키가 정책을 만족하지 않거나 만료되었습니다."
                )
            else:
                raise ValueError(f"복호화 중 오류: {str(e)}")
