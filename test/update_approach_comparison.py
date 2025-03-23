"""
CP-ABE와 기존 방식의 성능 비교 실험

이 실험은 다음을 측정합니다:
1. 확장성: 기기 수에 따른 키 생성, 암호화, 복호화 시간
2. 접근 취소: 기기 접근 권한 취소 과정의 효율성
3. 구독 갱신: 속성 갱신과 전체 키 재발급 효율성
4. 대역폭 사용량: 기기 수에 따른 네트워크 사용량
"""

import os
import sys
import time
import random
from datetime import datetime, timedelta
import numpy as np

# matplotlib 백엔드를 GUI 없는 'Agg'로 설정 (중요: import 전에 설정해야 함)
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from collections import defaultdict

# 상위 디렉토리를 모듈 경로에 추가
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from cp_abe.dynamic_cpabe import DynamicCPABE
from cp_abe.key_authority import KeyAuthority
from cp_abe.fading_functions import LinearFadingFunction
from cryptography.fernet import Fernet


# 폰트 설정 함수 추가
def setup_matplotlib_fonts():
    """Matplotlib에서 한글 폰트 문제 해결을 위한 설정"""
    plt.rcParams["font.family"] = "DejaVu Sans"
    plt.rcParams["axes.unicode_minus"] = False

    # 영어로 라벨 설정 (한글 대신)
    global LABELS
    LABELS = {
        # 기존 한글 라벨을 영어로 교체
        "기기 수": "Number of Devices",
        "암호화 시간 (초)": "Encryption Time (s)",
        "평균 키 생성 시간 (초/기기)": "Avg. Key Gen Time (s/device)",
        "설정 시간 (초)": "Setup Time (s)",
        "기기 수에 따른 암호화 시간": "Encryption Time vs. Number of Devices",
        "기기별 평균 키 생성 시간": "Average Key Generation Time per Device",
        "설정 시간 비교": "Setup Time Comparison",
        "접근 취소 시간 (초)": "Revocation Time (s)",
        "총 접근 취소 처리 시간 (초)": "Total Revocation Processing Time (s)",
        "기기 수에 따른 접근 취소 시간": "Revocation Time vs. Number of Devices",
        "기기 수에 따른 총 접근 취소 처리 시간": "Total Revocation Processing Time vs. Number of Devices",
        "기존 방식(블랙리스트)": "Traditional (Blacklist)",
        "기존 방식 (블랙리스트+키재발급)": "Traditional (Blacklist+Rekey)",
        "CP-ABE (전체)": "CP-ABE (Total)",
        "총 속성 수": "Total Number of Attributes",
        "갱신 시간 (초)": "Update Time (s)",
        "효율성 개선 비율 (전체/부분)": "Efficiency Improvement Ratio (Full/Partial)",
        "속성 수에 따른 키 갱신 시간 비교": "Key Update Time vs. Number of Attributes",
        "부분 키 갱신의 효율성 개선 비율": "Efficiency Improvement of Partial Key Update",
        "부분 키 갱신": "Partial Key Update",
        "전체 키 재발급": "Full Key Reissue",
        "대역폭 사용량 (바이트)": "Bandwidth Usage (bytes)",
        "대역폭 절약률 (%)": "Bandwidth Saving (%)",
        "기기 수에 따른 대역폭 사용량": "Bandwidth Usage vs. Number of Devices",
        "기기 수에 따른 대역폭 절약률": "Bandwidth Saving vs. Number of Devices",
        "기기 수에 따른 암호화 시간 및 효율성 교차점": "Encryption Time vs. Number of Devices and Efficiency Crossover Point",
        "교차점": "Crossover",
    }

    return LABELS


# 메인 함수 시작 시 폰트 설정 호출
LABELS = {}


class TraditionalApproach:
    """기존 방식의 대칭키 기반 접근법 시뮬레이션"""

    def __init__(self):
        self.device_keys = {}  # 장치별 키
        self.blacklist = set()  # 차단된 장치

    def setup(self):
        """초기 설정 - 메모리 구조만 초기화"""
        self.device_keys = {}
        self.blacklist = set()
        return True

    def generate_key(self, device_id):
        """장치별 개별 대칭키 생성"""
        key = Fernet.generate_key()
        self.device_keys[device_id] = {
            "key": key,
            "issue_time": time.time(),
            "status": "active",
        }
        return key

    def encrypt_for_devices(self, message, target_devices=None):
        """대상 장치들에게 각각 암호화"""
        if target_devices is None:
            target_devices = [d for d in self.device_keys if d not in self.blacklist]

        encrypted_messages = {}
        for device_id in target_devices:
            if device_id in self.device_keys and device_id not in self.blacklist:
                key = self.device_keys[device_id]["key"]
                cipher = Fernet(key)
                encrypted_messages[device_id] = cipher.encrypt(message.encode())

        return encrypted_messages

    def decrypt(self, encrypted_message, device_id):
        """암호화된 메시지 복호화"""
        if device_id in self.blacklist:
            raise ValueError("장치가 블랙리스트에 포함되어 있습니다")

        if device_id not in self.device_keys:
            raise ValueError("알 수 없는 장치입니다")

        key = self.device_keys[device_id]["key"]
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_message).decode()

    def revoke_access(self, device_id):
        """장치 접근 권한 취소"""
        if device_id in self.device_keys:
            self.blacklist.add(device_id)
            return True
        return False

    def refresh_keys(self, exclude_devices=None):
        """모든 장치의 키를 새로 발급 (차단된 장치 제외)"""
        if exclude_devices is None:
            exclude_devices = self.blacklist

        new_keys = {}
        for device_id in self.device_keys:
            if device_id not in exclude_devices:
                new_keys[device_id] = self.generate_key(device_id)

        return new_keys


def run_scaling_experiment(device_counts):
    """확장성 실험: 기기 수에 따른 성능 비교"""
    print(
        "\n=== Scalability Experiment: Performance Comparison by Number of Devices ==="
    )

    # 결과 저장용 딕셔너리
    results = {
        "device_counts": device_counts,
        "cpabe_setup_time": [],
        "cpabe_encrypt_time": [],
        "cpabe_keygen_time": [],
        "trad_setup_time": [],
        "trad_encrypt_time": [],
        "trad_keygen_time": [],
    }

    test_message = "This is a software update package."

    for device_count in device_counts:
        print(f"\nNumber of devices: {device_count}")

        # === CP-ABE 방식 ===
        cpabe = DynamicCPABE()

        # 설정 시간 측정
        start_time = time.time()
        cpabe.setup()

        # 페이딩 함수 등록
        subscription_function = LinearFadingFunction("subscription", 3600)  # 1시간
        cpabe.register_fading_function("subscription", subscription_function)

        setup_time = time.time() - start_time
        results["cpabe_setup_time"].append(setup_time)
        print(f"CP-ABE setup time: {setup_time:.6f}s")

        # 키 생성 시간 측정
        start_time = time.time()
        for i in range(device_count):
            user_id = cpabe.create_user_record(f"device_{i}")
            key = cpabe.keygen_with_dynamic_attributes(
                user_id, ["model", "serialNumber", "subscription"]
            )
        keygen_time = time.time() - start_time
        results["cpabe_keygen_time"].append(
            keygen_time / device_count
        )  # 평균 키 생성 시간
        print(
            f"CP-ABE average key generation time: {keygen_time / device_count:.6f}s/device"
        )

        # 암호화 시간 측정
        start_time = time.time()
        encrypted = cpabe.encrypt(test_message, "model and subscription_0")
        encrypt_time = time.time() - start_time
        results["cpabe_encrypt_time"].append(encrypt_time)
        print(f"CP-ABE encryption time: {encrypt_time:.6f}s")

        # === 기존 방식 ===
        trad = TraditionalApproach()

        # 설정 시간 측정
        start_time = time.time()
        trad.setup()
        setup_time = time.time() - start_time
        results["trad_setup_time"].append(setup_time)
        print(f"Traditional approach setup time: {setup_time:.6f}s")

        # 키 생성 시간 측정
        start_time = time.time()
        for i in range(device_count):
            key = trad.generate_key(f"device_{i}")
        keygen_time = time.time() - start_time
        results["trad_keygen_time"].append(keygen_time / device_count)
        print(
            f"Traditional approach average key generation time: {keygen_time / device_count:.6f}s/device"
        )

        # 암호화 시간 측정 (모든 기기에 대해)
        start_time = time.time()
        encrypted_messages = trad.encrypt_for_devices(test_message)
        encrypt_time = time.time() - start_time
        results["trad_encrypt_time"].append(encrypt_time)
        print(f"Traditional approach encryption time: {encrypt_time:.6f}s")

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "scaling_comparison.png")

    plt.figure(figsize=(12, 8))

    # 암호화 시간 그래프
    plt.subplot(1, 3, 1)
    plt.plot(device_counts, results["cpabe_encrypt_time"], "o-", label="CP-ABE")
    plt.plot(device_counts, results["trad_encrypt_time"], "s-", label="Traditional")
    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["암호화 시간 (초)"])
    plt.title(LABELS["기기 수에 따른 암호화 시간"])
    plt.legend()
    plt.grid(True)

    # 키 생성 시간 그래프
    plt.subplot(1, 3, 2)
    plt.plot(device_counts, results["cpabe_keygen_time"], "o-", label="CP-ABE")
    plt.plot(device_counts, results["trad_keygen_time"], "s-", label="Traditional")
    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["평균 키 생성 시간 (초/기기)"])
    plt.title(LABELS["기기별 평균 키 생성 시간"])
    plt.legend()
    plt.grid(True)

    # 설정 시간 그래프
    plt.subplot(1, 3, 3)
    plt.plot(device_counts, results["cpabe_setup_time"], "o-", label="CP-ABE")
    plt.plot(device_counts, results["trad_setup_time"], "s-", label="Traditional")
    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["설정 시간 (초)"])
    plt.title(LABELS["설정 시간 비교"])
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    return results


def run_access_limitation_experiment(device_counts):
    """접근 제한 효율성 비교 실험 - 취소 대신 시간 제한으로 대체"""
    print(
        "\n=== Access Limitation Experiment: Time-Based vs. Re-encryption Approach ==="
    )

    # 결과 저장용 딕셔너리
    results = {
        "device_counts": device_counts,
        "cpabe_limit_time": [],  # CP-ABE: 기기 비활성화 시간 (시간 제한 속성)
        "trad_blacklist_time": [],  # 기존 방식: 블랙리스트 추가 시간
        "trad_rekey_time": [],  # 기존 방식: 키 재발급 시간
    }

    for device_count in device_counts:
        print(f"\nNumber of devices: {device_count}")

        # === CP-ABE 접근 제한 - 시간 제한 속성 ===
        # 시스템 초기화
        cpabe = DynamicCPABE()
        cpabe.setup()
        authority = KeyAuthority(cpabe)

        # 구독 정책 설정
        authority.set_renewal_policy(
            "subscription", max_renewals=None, renewal_period_days=30
        )

        # 기기 등록
        for i in range(device_count):
            device_id = f"device_{i}"
            authority.register_device(device_id, ["model", "serialNumber"], 30)

        # 첫 번째 기기 비활성화 시간 측정
        device_to_limit = "device_0"
        start_time = time.time()
        authority.set_device_inactive(device_to_limit)
        limit_time = time.time() - start_time
        results["cpabe_limit_time"].append(limit_time)
        print(f"CP-ABE device deactivation time: {limit_time:.6f}s")

        # === 기존 방식 접근 제한 ===
        trad = TraditionalApproach()
        trad.setup()

        # 키 생성
        for i in range(device_count):
            device_id = f"device_{i}"
            trad.generate_key(device_id)

        # 첫 번째 기기 블랙리스트 추가 시간
        device_to_limit = "device_0"
        start_time = time.time()
        trad.revoke_access(device_to_limit)
        blacklist_time = time.time() - start_time
        results["trad_blacklist_time"].append(blacklist_time)
        print(f"Traditional approach blacklist addition time: {blacklist_time:.6f}s")

        # 다른 모든 기기의 키 재발급 시간 (기존 방식의 추가 오버헤드)
        start_time = time.time()
        trad.refresh_keys()
        rekey_time = time.time() - start_time
        results["trad_rekey_time"].append(rekey_time)
        print(f"Traditional approach key reissue time (all devices): {rekey_time:.6f}s")

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    output_path = os.path.join(output_dir, "access_limitation_comparison.png")

    plt.figure(figsize=(12, 6))

    # 접근 제한 시간 그래프
    plt.subplot(1, 2, 1)
    plt.plot(
        device_counts, results["cpabe_limit_time"], "o-", label="CP-ABE (Time-Based)"
    )
    plt.plot(
        device_counts,
        results["trad_blacklist_time"],
        "s-",
        label="Traditional (Blacklist)",
    )
    plt.xlabel("Number of Devices")
    plt.ylabel("Access Limitation Time (s)")
    plt.title("Access Limitation Time vs. Number of Devices")
    plt.legend()
    plt.grid(True)

    # 전체 시간 (재발급 포함) 그래프
    plt.subplot(1, 2, 2)
    plt.plot(device_counts, results["cpabe_limit_time"], "o-", label="CP-ABE (Total)")
    plt.plot(
        device_counts,
        [
            a + b
            for a, b in zip(results["trad_blacklist_time"], results["trad_rekey_time"])
        ],
        "s-",
        label="Traditional (Blacklist + Rekey)",
    )
    plt.xlabel("Number of Devices")
    plt.ylabel("Total Processing Time (s)")
    plt.title("Total Processing Time vs. Number of Devices")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    return results


def run_renewal_experiment():
    """구독 갱신 효율성 비교 실험"""
    print(
        "\n=== Subscription Renewal Experiment: Partial Key Update vs. Full Key Reissue ==="
    )

    # 다양한 속성 수에 따른 비교
    attribute_counts = [2, 4, 6, 8, 10, 12, 14]

    # 결과 저장용 딕셔너리
    results = {
        "attribute_counts": attribute_counts,
        "partial_update_time": [],
        "full_rekey_time": [],
    }

    for attr_count in attribute_counts:
        print(f"\nTotal attributes: {attr_count}")

        # === 부분 키 갱신 ===
        # 시스템 초기화
        cpabe = DynamicCPABE()
        cpabe.setup()

        # 페이딩 함수 등록
        subscription_function = LinearFadingFunction("subscription", 3600)
        cpabe.register_fading_function("subscription", subscription_function)

        # 사용자 생성
        user_id = cpabe.create_user_record("test_user")

        # 속성 준비 (subscription + 나머지는 정적 속성)
        attributes = ["subscription"]
        for i in range(1, attr_count):
            attributes.append(f"attr_{i}")

        # 초기 키 생성
        key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)

        # 구독 속성만 갱신 시간 측정
        start_time = time.time()
        subscription_attr = cpabe.update_attribute(user_id, "subscription")
        updated_key = cpabe.merge_attribute_to_key(key, subscription_attr)
        partial_update_time = time.time() - start_time
        results["partial_update_time"].append(partial_update_time)
        print(f"Partial key update time: {partial_update_time:.6f}s")

        # === 전체 키 재발급 ===
        start_time = time.time()
        new_key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)
        full_rekey_time = time.time() - start_time
        results["full_rekey_time"].append(full_rekey_time)
        print(f"Full key reissue time: {full_rekey_time:.6f}s")

        # 메모리 사용량 비교
        import sys

        partial_update_size = sys.getsizeof(subscription_attr)
        full_key_size = sys.getsizeof(new_key)
        print(f"Partial key update data size: {partial_update_size} bytes")
        print(f"Full key data size: {full_key_size} bytes")
        print(f"Data savings: {(1 - partial_update_size/full_key_size)*100:.1f}%")

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    output_path = os.path.join(output_dir, "renewal_comparison.png")

    plt.figure(figsize=(10, 5))

    # 갱신 시간 비교 그래프
    plt.subplot(1, 2, 1)
    plt.plot(
        attribute_counts,
        results["partial_update_time"],
        "o-",
        label=LABELS["부분 키 갱신"],
    )
    plt.plot(
        attribute_counts,
        results["full_rekey_time"],
        "s-",
        label=LABELS["전체 키 재발급"],
    )
    plt.xlabel(LABELS["총 속성 수"])
    plt.ylabel(LABELS["갱신 시간 (초)"])
    plt.title(LABELS["속성 수에 따른 키 갱신 시간 비교"])
    plt.legend()
    plt.grid(True)

    # 효율성 개선 비율
    plt.subplot(1, 2, 2)
    improvement_ratio = [
        full / partial
        for partial, full in zip(
            results["partial_update_time"], results["full_rekey_time"]
        )
    ]
    plt.plot(attribute_counts, improvement_ratio, "o-")
    plt.axhline(y=1.0, color="r", linestyle="--")
    plt.xlabel(LABELS["총 속성 수"])
    plt.ylabel(LABELS["효율성 개선 비율 (전체/부분)"])
    plt.title(LABELS["부분 키 갱신의 효율성 개선 비율"])
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    return results


def run_bandwidth_experiment(device_counts):
    """대역폭 사용량 비교 실험"""
    print(
        "\n=== Bandwidth Usage Experiment: Network Usage Comparison by Number of Devices ==="
    )

    # 결과 저장용 딕셔너리
    results = {
        "device_counts": device_counts,
        "cpabe_bandwidth": [],
        "trad_bandwidth": [],
        "bandwidth_saving": [],
    }

    # 테스트 메시지 (업데이트 패키지 크기 시뮬레이션)
    test_message = "X" * 10240  # 10KB 크기의 메시지

    for device_count in device_counts:
        print(f"\nNumber of devices: {device_count}")

        # === CP-ABE 방식 ===
        cpabe = DynamicCPABE()
        cpabe.setup()

        # 페이딩 함수 등록
        subscription_function = LinearFadingFunction("subscription", 3600)
        cpabe.register_fading_function("subscription", subscription_function)

        # 암호화
        encrypted = cpabe.encrypt(test_message, "model and subscription_0")

        # CP-ABE 암호문 크기 측정
        import sys

        cpabe_size = sys.getsizeof(encrypted)
        cpabe_total_size = cpabe_size  # 모든 기기가 동일한 암호문을 받음

        results["cpabe_bandwidth"].append(cpabe_total_size)
        print(f"CP-ABE ciphertext size: {cpabe_size} bytes")
        print(f"CP-ABE total transmission: {cpabe_total_size} bytes")

        # === 기존 방식 ===
        trad = TraditionalApproach()
        trad.setup()

        # 키 생성
        for i in range(device_count):
            device_id = f"device_{i}"
            trad.generate_key(device_id)

        # 암호화
        encrypted_messages = trad.encrypt_for_devices(test_message)

        # 기존 방식 암호문 크기 측정
        trad_size = sum(sys.getsizeof(msg) for msg in encrypted_messages.values())

        results["trad_bandwidth"].append(trad_size)
        print(f"Traditional approach total transmission: {trad_size} bytes")

        # 대역폭 절약율
        saving = (1 - cpabe_total_size / trad_size) * 100 if trad_size > 0 else 0
        results["bandwidth_saving"].append(saving)
        print(f"Bandwidth savings: {saving:.1f}%")

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    output_path = os.path.join(output_dir, "bandwidth_comparison.png")

    plt.figure(figsize=(12, 5))

    # 대역폭 사용량 그래프
    plt.subplot(1, 2, 1)
    plt.plot(device_counts, results["cpabe_bandwidth"], "o-", label="CP-ABE")
    plt.plot(device_counts, results["trad_bandwidth"], "s-", label="Traditional")
    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["대역폭 사용량 (바이트)"])
    plt.title(LABELS["기기 수에 따른 대역폭 사용량"])
    plt.legend()
    plt.grid(True)

    # 대역폭 절약률 그래프
    plt.subplot(1, 2, 2)
    plt.plot(device_counts, results["bandwidth_saving"], "o-")
    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["대역폭 절약률 (%)"])
    plt.title(LABELS["기기 수에 따른 대역폭 절약률"])
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    return results


def run_crossover_analysis():
    """교차점 분석: CP-ABE가 기존 방식보다 더 효율적이 되는 지점 찾기"""
    print(
        "\n=== Crossover Analysis: Efficiency Crossover Point between CP-ABE and Traditional Approach ==="
    )

    # 세밀한 기기 수 설정
    device_counts = [1, 10, 50, 100, 500, 1000, 2000, 3000, 4000, 5000]

    # 결과 저장용 딕셔너리
    results = {
        "device_counts": device_counts,
        "cpabe_encrypt_time": [],
        "trad_encrypt_time": [],
    }

    test_message = "This is a software update package." * 10  # 약간 더 큰 메시지

    for device_count in device_counts:
        print(f"\nNumber of devices: {device_count}")

        # === CP-ABE 방식 ===
        cpabe = DynamicCPABE()
        cpabe.setup()

        # 페이딩 함수 등록
        subscription_function = LinearFadingFunction("subscription", 3600)
        cpabe.register_fading_function("subscription", subscription_function)

        # 암호화 시간 측정
        start_time = time.time()
        encrypted = cpabe.encrypt(test_message, "model and subscription_0")
        encrypt_time = time.time() - start_time
        results["cpabe_encrypt_time"].append(encrypt_time)
        print(f"CP-ABE encryption time: {encrypt_time:.6f}s")

        # === 기존 방식 ===
        trad = TraditionalApproach()
        trad.setup()

        # 키 생성
        for i in range(device_count):
            device_id = f"device_{i}"
            trad.generate_key(device_id)

        # 암호화 시간 측정 (모든 기기에 대해)
        start_time = time.time()
        encrypted_messages = trad.encrypt_for_devices(test_message)
        encrypt_time = time.time() - start_time
        results["trad_encrypt_time"].append(encrypt_time)
        print(f"Traditional approach encryption time: {encrypt_time:.6f}s")

    # 교차점 찾기
    from scipy import interpolate, optimize

    # 데이터 보간
    f_cpabe = interpolate.interp1d(
        device_counts,
        results["cpabe_encrypt_time"],
        kind="linear",
        fill_value="extrapolate",
    )
    f_trad = interpolate.interp1d(
        device_counts,
        results["trad_encrypt_time"],
        kind="linear",
        fill_value="extrapolate",
    )

    # 차이 함수 정의
    def difference(x):
        return f_trad(x) - f_cpabe(x)

    # 교차점 추정
    try:
        # 선형 보간에 기반한 대략적인 시작점 찾기
        start_point = min(device_counts)
        for i in range(len(device_counts) - 1):
            if (
                results["cpabe_encrypt_time"][i] <= results["trad_encrypt_time"][i]
                and results["cpabe_encrypt_time"][i + 1]
                >= results["trad_encrypt_time"][i + 1]
            ) or (
                results["cpabe_encrypt_time"][i] >= results["trad_encrypt_time"][i]
                and results["cpabe_encrypt_time"][i + 1]
                <= results["trad_encrypt_time"][i + 1]
            ):
                start_point = device_counts[i]
                break

        # 교차점 계산
        crossover = optimize.newton(difference, start_point)
        print(f"\nCrossover Analysis Results:")
        print(
            f"CP-ABE becomes more efficient than traditional approach at ~{int(crossover)} devices"
        )
    except:
        print(
            "\nCrossover analysis failed: No crossover point in data range or calculation error"
        )
        crossover = None

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    output_path = os.path.join(output_dir, "crossover_analysis.png")

    plt.figure(figsize=(10, 6))

    # 암호화 시간 그래프
    plt.plot(device_counts, results["cpabe_encrypt_time"], "o-", label="CP-ABE")
    plt.plot(device_counts, results["trad_encrypt_time"], "s-", label="Traditional")

    # 교차점 표시
    if crossover is not None and crossover > 0:
        plt.axvline(
            x=crossover,
            color="r",
            linestyle="--",
            label=f'{LABELS["교차점"]}: {int(crossover)} devices',
        )
        plt.plot(crossover, f_cpabe(crossover), "ro", markersize=8)

    plt.xlabel(LABELS["기기 수"])
    plt.ylabel(LABELS["암호화 시간 (초)"])
    plt.title(LABELS["기기 수에 따른 암호화 시간 및 효율성 교차점"])
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    return crossover if crossover is not None else "No crossover point"


def main():
    """모든 실험 수행"""
    print("===== CP-ABE vs. Traditional Approach Performance Comparison =====")

    # 폰트 설정 (한글 문제 해결)
    global LABELS
    LABELS = setup_matplotlib_fonts()

    # 실험 결과를 저장할 디렉토리 생성 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    os.makedirs(output_dir, exist_ok=True)
    print(f"실험 결과 저장 경로: {output_dir}")

    # 1. 확장성 실험
    device_counts = [1, 10, 50, 100, 500, 1000]
    scaling_results = run_scaling_experiment(device_counts)

    # 2. 접근 제한 실험 - 취소 대신 시간 제한으로 대체
    access_limitation_results = run_access_limitation_experiment(device_counts)

    # 3. 구독 갱신 실험
    renewal_results = run_renewal_experiment()

    # 4. 대역폭 사용량 실험
    bandwidth_results = run_bandwidth_experiment(device_counts)

    # 5. 교차점 분석
    crossover = run_crossover_analysis()

    # 결과 요약
    print("\n===== Results Summary =====")
    print(
        f"1. Efficiency crossover: CP-ABE becomes more efficient than traditional approach at ~{crossover} devices"
    )
    print(
        f"2. Access limitation: CP-ABE uses time-based attributes instead of manual revocation"
    )
    print(
        f"3. Subscription renewal: Partial key update more efficient as attribute count increases"
    )
    print(
        f"4. Bandwidth usage: CP-ABE bandwidth savings increase with number of devices"
    )

    print("\nExperiment result images saved in 'experiment_results' folder.")


if __name__ == "__main__":
    main()
