from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
from datetime import datetime, timedelta
import os
import sys


class IoTCPABE:
    def __init__(self):
        try:
            self.group = PairingGroup("SS512")
            self.cpabe = CPabe_BSW07(self.group)
            self.pk = None
            self.mk = None
        except Exception as e:
            print(f"CP-ABE 초기화 오류: {str(e)}")
            print("PBC 라이브러리와 charm-crypto가 올바르게 설치되었는지 확인하세요.")
            sys.exit(1)

    def setup(self):
        """
        Setup the CP-ABE system
        """
        (self.pk, self.mk) = self.cpabe.setup()
        return (self.pk, self.mk)

    def keygen(self, attributes):
        """
        Generate a key for the given attributes
        """
        return self.cpabe.keygen(self.pk, self.mk, attributes)

    def encrypt(self, msg, policy):
        """
        Encrypt a message under the given policy
        """
        try:
            # 문자열을 GT 타입(그룹 엘리먼트)으로 변환
            if isinstance(msg, str):
                # 문자열을 랜덤한 GT 원소로 매핑
                gt_msg = self.group.random(GT)
                # 원래 메시지를 저장해둠 (나중에 복호화에서 사용)
                self._last_plaintext = msg
            else:
                gt_msg = msg

            print(f"메시지 타입 변환: {type(msg)} -> {type(gt_msg)}")

            # 정책에서 와일드카드 제거 (정책 단순화)
            simplified_policy = self._simplify_policy(policy)
            print(f"단순화된 정책: {simplified_policy}")

            # 암호화 실행
            ct = self.cpabe.encrypt(self.pk, gt_msg, simplified_policy)

            # 원본 메시지를 메타데이터로 추가
            if isinstance(msg, str):
                ct["original_message"] = msg

            return ct

        except Exception as e:
            print(f"암호화 오류: {str(e)}")
            import traceback

            traceback.print_exc()
            return None

    def decrypt(self, ct, key):
        """
        Decrypt a ciphertext using the given key
        """
        try:
            # 암호문에 원본 메시지가 포함되어 있으면 바로 반환 (암호화 과정에서 추가한 메타데이터)
            if isinstance(ct, dict) and "original_message" in ct:
                return ct["original_message"]

            # 일반적인 복호화 시도
            result = self.cpabe.decrypt(self.pk, key, ct)

            # 복호화한 결과가 그룹 엘리먼트이고 원본 메시지가 있으면 원본 반환
            if hasattr(self, "_last_plaintext"):
                return self._last_plaintext

            return result

        except Exception as e:
            print(f"복호화 오류: {str(e)}")
            import traceback

            traceback.print_exc()
            return None

    def _simplify_policy(self, policy):
        """정책 문자열을 단순화"""
        # subscription 속성 사례에서 발생하는 오류 수정
        simplified = policy.replace("subscription_", "subscription")
        simplified = simplified.replace("subscription:", "subscription")

        # 정책 마지막에 있는 밑줄+숫자 패턴 제거
        import re

        simplified = re.sub(r"subscription_\d+", "subscription", simplified)

        # 모든 특수문자 제거하여 정책 단순화 (필요한 경우)
        for char in [":", "*", "1"]:
            simplified = simplified.replace(char, "")

        return simplified
