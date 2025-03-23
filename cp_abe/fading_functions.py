import time
import math
from abc import ABC, abstractmethod


class FadingFunction(ABC):
    """
    페이딩 함수 추상 기본 클래스

    논문에서 설명한 fading function의 기본 인터페이스를 정의합니다.
    페이딩 함수는 시간이 지남에 따라 속성 값을 변화시킵니다.
    """

    def __init__(self, attribute_name):
        self.attribute_name = attribute_name
        self.base_time = time.time()  # 기준 시간

    @abstractmethod
    def compute_current_value(self, current_time=None):
        """현재 시간 기준으로 속성 값 계산"""
        pass

    @abstractmethod
    def is_valid(self, attribute_value, current_time=None):
        """주어진 속성 값이 현재 시간에 유효한지 확인"""
        pass


class LinearFadingFunction(FadingFunction):
    """
    선형 페이딩 함수 - 일정 시간마다 값이 증가
    """

    def __init__(self, attribute_name, lifetime_seconds):
        super().__init__(attribute_name)
        self.lifetime_seconds = lifetime_seconds

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        interval = math.floor(time_diff / self.lifetime_seconds)

        # 시간에 따라 선형적으로 증가하는 값 계산
        current_value = f"{self.attribute_name}_{interval}"
        return current_value

    def is_valid(self, attribute_value, current_time=None):
        current_value = self.compute_current_value(current_time)
        return attribute_value == current_value


class StepFadingFunction(FadingFunction):
    """
    계단식 페이딩 함수 - 특정 임계값에 도달할 때마다 값이 변화
    """

    def __init__(self, attribute_name, lifetime_seconds, steps=5):
        super().__init__(attribute_name)
        self.lifetime_seconds = lifetime_seconds
        self.steps = steps

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        step_size = self.lifetime_seconds / self.steps
        current_step = math.floor(time_diff / step_size)

        # 계단식으로 변화하는 속성값 계산
        current_value = f"{self.attribute_name}_step{current_step}"
        return current_value

    def is_valid(self, attribute_value, current_time=None):
        current_value = self.compute_current_value(current_time)
        return attribute_value == current_value


class LocationFadingFunction(FadingFunction):
    """
    위치 속성을 위한 특수 페이딩 함수
    """

    def __init__(self, location_id, granularity, lifetime_seconds):
        super().__init__(f"loc_{location_id}_{granularity}")
        self.location_id = location_id
        self.granularity = granularity  # 1=coarse, 2=medium, 3=fine
        self.lifetime_seconds = lifetime_seconds

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        # 세분화 수준에 따라 다른 lifetime 사용
        adjusted_lifetime = self.lifetime_seconds / self.granularity
        interval = math.floor(time_diff / adjusted_lifetime)

        # 위치 속성의 현재 값 계산
        current_value = f"loc_{self.location_id}_{self.granularity}_{interval}"
        return current_value

    def is_valid(self, attribute_value, current_time=None):
        current_value = self.compute_current_value(current_time)
        return attribute_value == current_value


class HardExpiryFadingFunction(FadingFunction):
    """
    Hard Expiry 페이딩 함수 - 특정 시간이 지나면 무조건 만료됨
    """

    def __init__(self, attribute_name, lifetime_seconds, max_renewals=None):
        super().__init__(attribute_name)
        self.lifetime_seconds = lifetime_seconds
        self.max_renewals = max_renewals  # 최대 갱신 횟수

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        # 경과 시간 계산
        time_diff = current_time - self.base_time

        # 간격 계산
        interval = math.floor(time_diff / self.lifetime_seconds)

        # 최대 갱신 횟수 초과 체크
        if self.max_renewals is not None and interval > self.max_renewals:
            return f"{self.attribute_name}_expired"

        return f"{self.attribute_name}_{interval}"

    def is_valid(self, attribute_value, current_time=None):
        """
        Hard expiry - 정확히 같은 값이어야만 유효
        """
        current_value = self.compute_current_value(current_time)
        # expired 값은 항상 유효하지 않음
        if current_value.endswith("_expired") or attribute_value.endswith("_expired"):
            return False
        return attribute_value == current_value
