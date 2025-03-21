from datetime import datetime, timedelta
import math
import time


class FadingFunction:
    """
    속성 페이딩 함수의 기본 클래스
    각 속성은 시간에 따라 값이 변하는 자체 페이딩 함수를 가질 수 있음
    """

    def __init__(self, attribute_base_value, lifetime_seconds):
        self.attribute_base_value = attribute_base_value
        self.lifetime_seconds = lifetime_seconds
        self.base_time = time.time()  # 초기화 시점의 시간

    def compute_current_value(self, current_time=None):
        """
        현재 시간에 기반한 속성 값 계산
        논문의 예시: Att_Current_Value = Att_Base_Value × ⌊(t - Base_Time) / 60min⌋
        """
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        interval = math.floor(time_diff / self.lifetime_seconds)

        # 속성 기본값과 시간 간격에 기반한 현재 값 계산
        current_value = f"{self.attribute_base_value}_{interval}"
        return current_value

    def is_valid(self, attribute_value, current_time=None):
        """
        주어진 속성 값이 현재 유효한지 확인
        """
        current_value = self.compute_current_value(current_time)
        return attribute_value == current_value


class LinearFadingFunction(FadingFunction):
    """
    선형 페이딩 함수 - 일정 시간마다 값이 증가
    """

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        interval = math.floor(time_diff / self.lifetime_seconds)

        # 시간에 따라 선형적으로 증가하는 값 계산
        current_value = f"{self.attribute_base_value}_{interval}"
        return current_value


class StepFadingFunction(FadingFunction):
    """
    계단식 페이딩 함수 - 특정 임계값에 도달할 때마다 값이 변화
    """

    def __init__(self, attribute_base_value, lifetime_seconds, steps=5):
        super().__init__(attribute_base_value, lifetime_seconds)
        self.steps = steps

    def compute_current_value(self, current_time=None):
        if current_time is None:
            current_time = time.time()

        time_diff = current_time - self.base_time
        step_size = self.lifetime_seconds / self.steps
        current_step = math.floor(time_diff / step_size)

        # 계단식으로 변화하는 속성값 계산
        current_value = f"{self.attribute_base_value}_step{current_step}"
        return current_value


class LocationFadingFunction(FadingFunction):
    """
    위치 속성을 위한 특수 페이딩 함수
    """

    def __init__(self, location_id, granularity, lifetime_seconds):
        super().__init__(f"loc_{location_id}_{granularity}", lifetime_seconds)
        self.location_id = location_id
        self.granularity = granularity  # 1=coarse, 2=medium, 3=fine

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
