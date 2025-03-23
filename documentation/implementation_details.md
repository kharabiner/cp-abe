# CP-ABE 구현 세부사항

## 1. 속성 구조 및 관리

### 1.1 정적 속성 (Static Attributes)

정적 속성은 기기의 기본적인 특성을 나타내며, 시간에 따라 변하지 않습니다.

- **모델(model)**: 기기의 모델 정보를 나타냅니다.
  - 예: "model", "modelA", "modelB" 등
  
- **일련번호(serialNumber)**: 기기의 고유 일련번호를 나타냅니다.
  - 예: "serialNumber", "serialNumber1", "serialNumber2" 등

### 1.2 동적 속성 (Dynamic Attributes)

동적 속성은 시간이 지남에 따라 값이 변하는 속성입니다.

- **구독(subscription)**: 사용자의 구독 상태를 나타냅니다.
  - 값 형식: "subscription_[interval]"
  - 예: "subscription_0" (초기 구독), "subscription_1" (첫 번째 간격 이후)

- **보증(warranty)**: 기기의 보증 상태를 나타냅니다.
  - 값 형식: "warranty_[interval]"
  - 예: "warranty_0" (초기 보증 기간), "warranty_1" (첫 번째 갱신 후)

## 2. 페이딩 함수 구현

페이딩 함수는 동적 속성의 값을 시간에 따라 자동으로 변경하는 메커니즘입니다.

### 2.1 LinearFadingFunction

시간이 경과함에 따라 속성값이 선형적으로 변화합니다:

```python
def compute_current_value(self, current_time=None):
    if current_time is None:
        current_time = time.time()
        
    time_diff = current_time - self.base_time
    interval = math.floor(time_diff / self.lifetime_seconds)
    
    return f"{self.attribute_name}_{interval}"
```

### 2.2 HardExpiryFadingFunction

정해진 횟수만큼 갱신이 가능하고, 그 이후에는 영구적으로 만료됩니다:

```python
def compute_current_value(self, current_time=None):
    if current_time is None:
        current_time = time.time()
        
    time_diff = current_time - self.base_time
    interval = math.floor(time_diff / self.lifetime_seconds)
    
    if self.max_renewals is not None and interval > self.max_renewals:
        return f"{self.attribute_name}_expired"
        
    return f"{self.attribute_name}_{interval}"
```

## 3. 키 갱신 메커니즘

### 3.1 속성 갱신 (UpdateAttribute)

특정 속성만 갱신하는 함수:

```python
def update_attribute(self, user_id, attribute_name):
    # 속성의 새 값 계산
    new_value = self.compute_attribute_value(attribute_name)
    
    return {
        "attribute_name": attribute_name,
        "attribute_value": new_value,
        "issue_time": time.time(),
    }
```

### 3.2 키 병합 (MergeKey)

기존 키에 새 속성을 병합하는 함수:

```python
def merge_attribute_to_key(self, key, new_attr):
    # 새 속성 정보 추출
    attr_name = new_attr["attribute_name"]
    attr_value = new_attr["attribute_value"]
    
    # 키에 새 속성값 업데이트
    key["dynamic_attributes"][attr_name] = attr_value
    
    # 속성 목록에 새 속성 추가
    sanitized_attr = self._sanitize_attribute(attr_value)
    if sanitized_attr not in key["S"]:
        key["S"].append(sanitized_attr)
        
    return key
```

## 4. 암호화 및 복호화 프로세스

### 4.1 동적 속성 암호화

```python
def encrypt_with_dynamic_attributes(self, msg, policy_attributes):
    # 동적 속성의 현재값 계산
    transformed_policy = []
    for attr in policy_attributes:
        if attr in ["subscription", "warranty"]:
            attr_value = self.compute_attribute_value(attr)
            transformed_policy.append(attr_value)
        else:
            transformed_policy.append(attr)
            
    # 변환된 정책으로 암호화
    return self.encrypt(msg, transformed_policy)
```

### 4.2 유효성 검사 및 복호화

```python
def decrypt(self, ciphertext, key):
    # 키 유효성 검사
    validity = self.check_key_validity(key)
    if not validity["valid"]:
        return False
        
    # 유효한 키로 복호화 시도
    return super().decrypt(ciphertext, key)
```

## 5. 키 인증 기관

키 인증 기관은 다음 기능을 담당합니다:

1. **기기 등록**: 새 기기에 초기 키 발급
2. **갱신 정책 관리**: 각 속성의 갱신 정책 설정 
3. **갱신 요청 처리**: 기기의 속성 갱신 요청 승인/거부
4. **접근 취소**: 부정 사용 기기의 접근 권한 취소
5. **기기 상태 관리**: 활성/비활성/취소 상태 추적

### 예시: 기기 등록 과정

```python
def register_device(self, device_id, initial_attributes, subscription_period_days=30):
    # 사용자 ID 생성
    user_id = self.cpabe.create_user_record(device_id)
    
    # 모든 속성 준비 (초기 속성 + 구독)
    complete_attributes = list(initial_attributes)
    if "subscription" not in complete_attributes:
        complete_attributes.append("subscription")
        
    # 키 생성
    key = self.cpabe.keygen_with_dynamic_attributes(user_id, complete_attributes)
    
    # 기기 정보 저장
    self.device_registry[device_id] = {
        "registration_date": datetime.now().isoformat(),
        "subscription_end": (datetime.now() + timedelta(days=subscription_period_days)).strftime("%Y-%m-%d"),
        "attributes": initial_attributes,
        "status": "active",
    }
    
    return key
```
