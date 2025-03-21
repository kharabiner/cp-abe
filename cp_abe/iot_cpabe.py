from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
from charm.schemes.abenc.abenc_bsw07 import CPabe_BSW07
import time
from datetime import datetime, timedelta
import json
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

    def save_keys(self, directory="keys"):
        """
        Save the public and master keys
        """
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(f"{directory}/pk.json", "w") as f:
            json.dump(self.group.serialize(self.pk), f)

        with open(f"{directory}/mk.json", "w") as f:
            json.dump(self.group.serialize(self.mk), f)

    def load_keys(self, directory="keys"):
        """
        Load the public and master keys
        """
        with open(f"{directory}/pk.json", "r") as f:
            self.pk = self.group.deserialize(json.load(f))

        with open(f"{directory}/mk.json", "r") as f:
            self.mk = self.group.deserialize(json.load(f))

    def keygen(self, attributes):
        """
        Generate a key for the given attributes
        """
        return self.cpabe.keygen(self.pk, self.mk, attributes)

    def encrypt(self, msg, policy):
        """
        Encrypt a message under the given policy
        """
        return self.cpabe.encrypt(self.pk, msg, policy)

    def decrypt(self, ct, key):
        """
        Decrypt a ciphertext using the given key
        """
        return self.cpabe.decrypt(self.pk, key, ct)
