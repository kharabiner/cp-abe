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

    # 키 저장 및 로드 기능은 제거 (직렬화 문제로 인해)

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
            # 문자열을 그룹 엘리먼트로 변환하지 않고 직접 전달
            # CP-ABE BSW07 구현체는 문자열을 직접 처리할 수 있음
            print(f"메시지 타입: {type(msg)}")
            print(f"정책: {policy}")

            # 정책 구문 확인
            policy = policy.replace("*", "1")  # 와일드카드 * 를 1로 변환

            return self.cpabe.encrypt(self.pk, msg, policy)
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
            result = self.cpabe.decrypt(self.pk, key, ct)
            return result
        except Exception as e:
            print(f"복호화 오류: {str(e)}")
            import traceback

            traceback.print_exc()
            return None
