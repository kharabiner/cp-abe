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

    # 디버그 모드 여부 확인
    debug_mode = os.environ.get("CP_ABE_DEBUG") == "1"

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
        # 최소한의 로깅만 수행
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
        "cpabe_limit_time": [],
        "trad_blacklist_time": [],
        "trad_rekey_time": [],
    }

    # 측정 횟수 증가 (더 정확한 평균값 계산을 위해)
    measurement_repeats = 5

    for device_count in device_counts:
        print(f"\nNumber of devices: {device_count}")

        # === CP-ABE 접근 제한 - 시간 제한 속성 ===
        # 측정 변동성 감소를 위해 여러 번 측정 후 평균 계산
        cpabe_limit_times = []

        for _ in range(measurement_repeats):
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

            # 메모리 청소를 위한 가비지 컬렉션 명시적 호출
            import gc

            gc.collect()

            # 첫 번째 기기 비활성화 시간 측정
            device_to_limit = "device_0"
            # time 충돌 문제 해결 - time 모듈 직접 import
            import time as time_module  # 별도 이름으로 임포트

            start_time = time_module.time()
            authority.set_device_inactive(device_to_limit)
            limit_time = time_module.time() - start_time
            cpabe_limit_times.append(limit_time)

        # 평균값 계산 (이상치 제거 후)
        if len(cpabe_limit_times) > 2:
            # 최대값과 최소값 제거 (이상치 제거)
            cpabe_limit_times.remove(max(cpabe_limit_times))
            cpabe_limit_times.remove(min(cpabe_limit_times))

        avg_cpabe_limit_time = sum(cpabe_limit_times) / len(cpabe_limit_times)
        results["cpabe_limit_time"].append(avg_cpabe_limit_time)
        print(
            f"CP-ABE device deactivation time: {avg_cpabe_limit_time:.6f}s (avg of {len(cpabe_limit_times)} measurements)"
        )

        # === 기존 방식 접근 제한 === (유사하게 여러 번 측정하여 평균 계산)
        trad_blacklist_times = []
        trad_rekey_times = []

        for _ in range(measurement_repeats):
            trad = TraditionalApproach()
            trad.setup()

            # 키 생성
            for i in range(device_count):
                device_id = f"device_{i}"
                trad.generate_key(device_id)

            # 첫 번째 기기 블랙리스트 추가 시간
            device_to_limit = "device_0"
            start_blacklist_time = time_module.time()  # time_module 사용
            trad.revoke_access(device_to_limit)
            blacklist_time = time_module.time() - start_blacklist_time
            trad_blacklist_times.append(blacklist_time)

            # 다른 모든 기기의 키 재발급 시간 (기존 방식의 추가 오버헤드)
            start_rekey_time = time_module.time()  # time_module 사용
            trad.refresh_keys()
            rekey_time = time_module.time() - start_rekey_time
            trad_rekey_times.append(rekey_time)

        # 평균값 계산 (이상치 제거 후)
        if len(trad_blacklist_times) > 2:
            trad_blacklist_times.remove(max(trad_blacklist_times))
            trad_blacklist_times.remove(min(trad_blacklist_times))

        if len(trad_rekey_times) > 2:
            trad_rekey_times.remove(max(trad_rekey_times))
            trad_rekey_times.remove(min(trad_rekey_times))

        avg_blacklist_time = sum(trad_blacklist_times) / len(trad_blacklist_times)
        avg_rekey_time = sum(trad_rekey_times) / len(trad_rekey_times)

        results["trad_blacklist_time"].append(avg_blacklist_time)
        results["trad_rekey_time"].append(avg_rekey_time)

        print(
            f"Traditional approach blacklist addition time: {avg_blacklist_time:.6f}s (avg of {len(trad_blacklist_times)} measurements)"
        )
        print(
            f"Traditional approach key reissue time (all devices): {avg_rekey_time:.6f}s (avg of {len(trad_rekey_times)} measurements)"
        )

    # 그래프 생성 및 저장
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

    # 추가: 이상치 탐지 및 표시
    plt.figure(figsize=(10, 6))
    plt.plot(
        device_counts, results["cpabe_limit_time"], "o-", label="CP-ABE (Measured)"
    )

    # 추세선 추가 (노이즈 제거)
    from scipy import optimize

    def linear_func(x, a, b):
        return a * x + b

    # 선형 추세선 계산
    popt, _ = optimize.curve_fit(
        linear_func, device_counts, results["cpabe_limit_time"]
    )
    trend_values = [linear_func(x, *popt) for x in device_counts]

    plt.plot(device_counts, trend_values, "r--", label="CP-ABE (Trend)")
    plt.xlabel("Number of Devices")
    plt.ylabel("Access Limitation Time (s)")
    plt.title("CP-ABE Access Limitation Time Analysis")
    plt.legend()
    plt.grid(True)

    # 이상치 표시
    threshold = 0.2  # 추세값과 20% 이상 차이나면 이상치로 표시
    for i, (count, time, trend) in enumerate(
        zip(device_counts, results["cpabe_limit_time"], trend_values)
    ):
        if abs(time - trend) / trend > threshold:
            plt.annotate(
                f"Outlier",
                xy=(count, time),
                xytext=(count, time * 1.2),
                arrowprops=dict(arrowstyle="->", color="red"),
            )

    outlier_path = os.path.join(output_dir, "access_limitation_outliers.png")
    plt.savefig(outlier_path)
    print(f"이상치 분석 그래프 저장됨: {outlier_path}")

    return results


def run_renewal_experiment():
    """구독 갱신 효율성 비교 실험 - 갱신 속성 수 영향 추가"""
    print(
        "\n=== Subscription Renewal Experiment: Partial Key Update vs. Full Key Reissue ==="
    )

    # 다양한 속성 수에 따른 비교
    attribute_counts = [2, 4, 6, 8, 10, 12, 14]

    # 결과 저장용 딕셔너리
    results = {
        "attribute_counts": attribute_counts,
        "partial_update_time_single": [],  # 단일 속성 갱신
        "partial_update_time_half": [],  # 절반 속성 갱신
        "partial_update_time_all": [],  # 전체 속성 갱신
        "full_rekey_time": [],  # 전체 키 재발급
    }

    for attr_count in attribute_counts:
        print(f"\nTotal attributes: {attr_count}")

        # === 시스템 초기화 ===
        cpabe = DynamicCPABE()
        cpabe.setup()

        # 페이딩 함수 등록
        for i in range(attr_count):
            attr_name = f"attr_{i}"
            fading_function = LinearFadingFunction(attr_name, 3600)
            cpabe.register_fading_function(attr_name, fading_function)

        # 사용자 생성
        user_id = cpabe.create_user_record("test_user")

        # 속성 준비 - 모두 동적 속성으로 설정
        attributes = [f"attr_{i}" for i in range(attr_count)]

        # 초기 키 생성
        key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)

        # 1. 단일 속성 갱신 (attr_0만 갱신)
        start_time = time.time()
        single_attr = cpabe.update_attribute(user_id, "attr_0")
        updated_key = cpabe.merge_attribute_to_key(key, single_attr)
        single_update_time = time.time() - start_time
        results["partial_update_time_single"].append(single_update_time)
        print(f"Single attribute update time: {single_update_time:.6f}s")

        # 2. 절반 속성 갱신
        if attr_count > 1:
            start_time = time.time()
            half_key = dict(key)
            half_attrs_count = attr_count // 2
            for i in range(half_attrs_count):
                attr_name = f"attr_{i}"
                attr = cpabe.update_attribute(user_id, attr_name)
                half_key = cpabe.merge_attribute_to_key(half_key, attr)
            half_update_time = time.time() - start_time
            results["partial_update_time_half"].append(half_update_time)
            print(
                f"Half attributes ({half_attrs_count}) update time: {half_update_time:.6f}s"
            )
        else:
            # 속성이 1개인 경우 단일 속성 시간과 동일
            results["partial_update_time_half"].append(single_update_time)

        # 3. 모든 속성 갱신 (부분 갱신 방식으로)
        start_time = time.time()
        all_key = dict(key)
        for i in range(attr_count):
            attr_name = f"attr_{i}"
            attr = cpabe.update_attribute(user_id, attr_name)
            all_key = cpabe.merge_attribute_to_key(all_key, attr)
        all_update_time = time.time() - start_time
        results["partial_update_time_all"].append(all_update_time)
        print(f"All attributes update time (partial method): {all_update_time:.6f}s")

        # 4. 전체 키 재발급 방식
        start_time = time.time()
        new_key = cpabe.keygen_with_dynamic_attributes(user_id, attributes)
        full_rekey_time = time.time() - start_time
        results["full_rekey_time"].append(full_rekey_time)
        print(f"Full key reissue time: {full_rekey_time:.6f}s")

        # 효율성 비교
        print(
            f"Efficiency ratio (full/single): {full_rekey_time / single_update_time:.2f}x"
        )
        if attr_count > 1:
            print(
                f"Efficiency ratio (full/half): {full_rekey_time / half_update_time:.2f}x"
            )
        print(
            f"Efficiency ratio (full/all partial): {full_rekey_time / all_update_time:.2f}x"
        )

    # 그래프 저장 - 절대 경로 사용
    output_dir = os.path.join(parent_dir, "experiment_results")
    output_path = os.path.join(output_dir, "renewal_comparison.png")

    plt.figure(figsize=(12, 10))

    # 1. 갱신 시간 비교 그래프
    plt.subplot(2, 1, 1)
    plt.plot(
        attribute_counts,
        results["partial_update_time_single"],
        "o-",
        label="Single Attribute Update",
    )
    plt.plot(
        attribute_counts,
        results["partial_update_time_half"],
        "s-",
        label="Half Attributes Update",
    )
    plt.plot(
        attribute_counts,
        results["partial_update_time_all"],
        "^-",
        label="All Attributes Update",
    )
    plt.plot(
        attribute_counts, results["full_rekey_time"], "d-", label="Full Key Reissue"
    )
    plt.xlabel("Total Number of Attributes")
    plt.ylabel("Update Time (s)")
    plt.title("Key Update Time vs. Number of Attributes")
    plt.legend()
    plt.grid(True)

    # 2. 효율성 개선 비율
    plt.subplot(2, 1, 2)
    improvement_ratio_single = [
        full / single
        for single, full in zip(
            results["partial_update_time_single"], results["full_rekey_time"]
        )
    ]
    improvement_ratio_half = [
        full / half
        for half, full in zip(
            results["partial_update_time_half"], results["full_rekey_time"]
        )
    ]
    improvement_ratio_all = [
        full / all_partial
        for all_partial, full in zip(
            results["partial_update_time_all"], results["full_rekey_time"]
        )
    ]

    plt.plot(
        attribute_counts,
        improvement_ratio_single,
        "o-",
        label="Single Attribute Update",
    )
    plt.plot(
        attribute_counts, improvement_ratio_half, "s-", label="Half Attributes Update"
    )
    plt.plot(
        attribute_counts, improvement_ratio_all, "^-", label="All Attributes Update"
    )
    plt.axhline(y=1.0, color="r", linestyle="--", label="Break-even point")
    plt.xlabel("Total Number of Attributes")
    plt.ylabel("Efficiency Ratio (Full/Partial)")
    plt.title("Efficiency Improvement of Partial Key Update")
    plt.legend()
    plt.grid(True)

    plt.tight_layout()
    plt.savefig(output_path)
    print(f"그래프 저장됨: {output_path}")

    # 교차점 찾기 (부분 갱신이 전체 갱신보다 느려지는 지점)
    crossover_points = {}

    # 갱신 속성 비율에 따른 교차점 분석
    for update_type, times in [
        ("single", results["partial_update_time_single"]),
        ("half", results["partial_update_time_half"]),
        ("all", results["partial_update_time_all"]),
    ]:
        try:
            from scipy import interpolate, optimize

            # 데이터 보간
            f_partial = interpolate.interp1d(
                attribute_counts, times, kind="linear", fill_value="extrapolate"
            )
            f_full = interpolate.interp1d(
                attribute_counts,
                results["full_rekey_time"],
                kind="linear",
                fill_value="extrapolate",
            )

            # 차이 함수 정의
            def difference(x):
                return f_partial(x) - f_full(x)

            # 교차점 추정
            x_range = np.linspace(
                min(attribute_counts), max(attribute_counts) * 2, 1000
            )
            for i in range(len(x_range) - 1):
                if difference(x_range[i]) * difference(x_range[i + 1]) <= 0:
                    # 부호 변화 지점 = 교차점
                    try:
                        crossover = optimize.brentq(
                            difference, x_range[i], x_range[i + 1]
                        )
                        crossover_points[update_type] = (
                            int(crossover) if crossover > 0 else "No crossover"
                        )
                        break
                    except:
                        crossover_points[update_type] = "Calculation error"

            if update_type not in crossover_points:
                # 범위 내에서 교차점을 찾지 못한 경우
                crossover_points[update_type] = "Not found in range"

        except Exception as e:
            crossover_points[update_type] = f"Analysis failed: {str(e)}"

    print("\n교차점 분석 결과 (부분 갱신이 전체 갱신보다 느려지는 속성 수):")
    for update_type, crossover in crossover_points.items():
        print(f"- {update_type} 속성 갱신: {crossover}")

    # 별도 그래프로 교차점 시각화
    output_path = os.path.join(output_dir, "renewal_crossover_analysis.png")
    plt.figure(figsize=(10, 6))

    # 확장된 범위로 교차점 시각화
    extended_attr_counts = list(attribute_counts) + [16, 18, 20, 22, 24, 26, 28, 30]

    # 보간 함수로 확장된 데이터 생성
    try:
        f_single = interpolate.interp1d(
            attribute_counts,
            results["partial_update_time_single"],
            kind="linear",
            fill_value="extrapolate",
        )
        f_half = interpolate.interp1d(
            attribute_counts,
            results["partial_update_time_half"],
            kind="linear",
            fill_value="extrapolate",
        )
        f_all = interpolate.interp1d(
            attribute_counts,
            results["partial_update_time_all"],
            kind="linear",
            fill_value="extrapolate",
        )
        f_full = interpolate.interp1d(
            attribute_counts,
            results["full_rekey_time"],
            kind="linear",
            fill_value="extrapolate",
        )

        extended_single = [f_single(x) for x in extended_attr_counts]
        extended_half = [f_half(x) for x in extended_attr_counts]
        extended_all = [f_all(x) for x in extended_attr_counts]
        extended_full = [f_full(x) for x in extended_attr_counts]

        plt.plot(
            extended_attr_counts, extended_single, "o-", label="Single Attribute Update"
        )
        plt.plot(
            extended_attr_counts, extended_half, "s-", label="Half Attributes Update"
        )
        plt.plot(
            extended_attr_counts, extended_all, "^-", label="All Attributes Update"
        )
        plt.plot(extended_attr_counts, extended_full, "d-", label="Full Key Reissue")

        # 교차점 표시
        for update_type, crossover in crossover_points.items():
            if isinstance(crossover, (int, float)):
                if update_type == "single":
                    plt.axvline(
                        x=crossover,
                        color="green",
                        linestyle="--",
                        label=f"Single Attr Crossover: ~{int(crossover)} attrs",
                    )
                elif update_type == "half":
                    plt.axvline(
                        x=crossover,
                        color="orange",
                        linestyle="--",
                        label=f"Half Attrs Crossover: ~{int(crossover)} attrs",
                    )
                elif update_type == "all":
                    plt.axvline(
                        x=crossover,
                        color="red",
                        linestyle="--",
                        label=f"All Attrs Crossover: ~{int(crossover)} attrs",
                    )

        plt.xlabel("Total Number of Attributes")
        plt.ylabel("Update Time (s)")
        plt.title("Key Update Time and Crossover Analysis")
        plt.legend()
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(output_path)
        print(f"교차점 분석 그래프 저장됨: {output_path}")

    except Exception as e:
        print(f"교차점 시각화 오류: {str(e)}")

    return {"results": results, "crossover_points": crossover_points}


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

    # 실험 환경 설정 - 로깅 제한
    os.environ["CP_ABE_DEBUG"] = "0"  # 디버그 로깅 비활성화

    # 1. 확장성 실험
    device_counts = [1, 10, 50, 100, 500, 1000]
    scaling_results = run_scaling_experiment(device_counts)

    # 2. 접근 제한 실험 - 취소 대신 시간 제한으로 대체
    access_limitation_results = run_access_limitation_experiment(device_counts)

    # 3. 구독 갱신 실험 - 개선된 버전
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

    # 갱신 결과 요약 업데이트
    if isinstance(renewal_results, dict) and "crossover_points" in renewal_results:
        crossovers = renewal_results["crossover_points"]
        print("3. Subscription renewal efficiency:")
        print(
            f"   - Single attribute update: efficient until {crossovers.get('single', 'N/A')} attributes"
        )
        print(
            f"   - Half attributes update: efficient until {crossovers.get('half', 'N/A')} attributes"
        )
        print(
            f"   - All attributes update: efficient until {crossovers.get('all', 'N/A')} attributes"
        )
    else:
        print(
            "3. Subscription renewal: Partial key update more efficient as attribute count increases"
        )

    print(
        f"4. Bandwidth usage: CP-ABE bandwidth savings increase with number of devices"
    )

    print("\nExperiment result images saved in 'experiment_results' folder.")


if __name__ == "__main__":
    main()
