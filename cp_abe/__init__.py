"""
CP-ABE 패키지 초기화 모듈

CP-ABE 관련 클래스와 기능을 구현한 패키지
"""

import sys
import os

# 모듈 로드 경로에 현재 디렉토리 추가
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

__all__ = [
    "IoTCPABE",
    "DynamicCPABE",
    "KeyAuthority",
    "LinearFadingFunction",
    "HardExpiryFadingFunction",
]

# 주요 클래스 임포트
from .iot_cpabe import IoTCPABE
from .dynamic_cpabe import DynamicCPABE
from .key_authority import KeyAuthority
from .fading_functions import LinearFadingFunction, HardExpiryFadingFunction


def initialize():
    """패키지 초기화 함수"""
    try:
        # 패키지 초기화 로직
        return True
    except Exception as e:
        print(f"CP-ABE 패키지 초기화 실패: {e}")
        return False


__version__ = "1.0.0"
