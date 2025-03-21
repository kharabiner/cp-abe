# IoT 소프트웨어 업데이트 프레임워크

본 프로젝트는 CP-ABE(Ciphertext-Policy Attribute-Based Encryption), Fading Function, 부분 키 갱신 기술을 활용한 IoT 소프트웨어 업데이트 프레임워크를 구현합니다.

## 주요 기능

1. **속성 기반 암호화(CP-ABE)**: IoT 기기의 모델, 일련번호, 지역 등의 속성을 기반으로 업데이트 패키지 암호화
2. **Fading Function**: 구독 기한과 같은 시간 제한 속성이 자동으로 만료되는 기능
3. **부분 키 갱신**: 만료된 키를 전체가 아닌 필요한 부분(만료된 속성)만 갱신

## 도커 환경에서 실행하기

```bash
# 도커 이미지 빌드
docker-compose build

# 기본 실행
docker-compose run cp-abe python main.py

# 여러 시뮬레이션 실행
docker-compose run cp-abe python simulation.py
docker-compose run cp-abe python dynamic_simulation.py
docker-compose run cp-abe python car_subscription_simulation.py
docker-compose run cp-abe python authority_simulation.py
docker-compose run cp-abe python subscription_model_simulation.py
docker-compose run cp-abe python partial_key_update_test.py
docker-compose run cp-abe python file_encryption.py
```

## 시뮬레이션 시나리오

### 1. 기본 시뮬레이션 (simulation.py)
- CP-ABE 키 생성, 암호화, 복호화 기본 동작
- 시간 경과에 따른 속성 만료 테스트
- 대규모 IoT 환경 시뮬레이션

### 2. 동적 속성 시뮬레이션 (dynamic_simulation.py)
- 페이딩 함수 기반 동적 속성 테스트
- 실시간 속성 페이딩 및 키 만료 모니터링
- HardExpiryFadingFunction을 사용한 속성 갱신 제한

### 3. 자동차 구독 서비스 시뮬레이션 (car_subscription_simulation.py)
- 차량 출고 시 정적 속성(모델) + 동적 속성(구독) 설정
- 구독 활성화/만료에 따른 프리미엄 콘텐츠 접근 테스트
- 구독 만료 후에도 기본 기능은 계속 사용 가능

### 4. 인증 기관 시뮬레이션 (authority_simulation.py)
- 키 관리 기관의 역할 시뮬레이션
- 갱신 정책 설정 및 기기별 갱신 제한
- 블랙리스트 및 기기 접근 권한 취소 기능

### 5. IoT 구독 모델 시뮬레이션 (subscription_model_simulation.py)
- 제조사가 출시한 IoT 기기의 전체 생애주기
- 사용자 구독 시작/만료/재구독 시나리오
- 제조사의 기기 지원 종료 처리

### 6. 부분 키 갱신 테스트 (partial_key_update_test.py)
- 키 구조 분석 및 부분 갱신 메커니즘 검증
- 정적 속성 보존 확인
- 동적 속성만 갱신되는지 확인
- 다양한 정책에 대한 암호화/복호화 테스트

### 7. 파일 암호화 데모 (file_encryption.py)
- CP-ABE와 AES 하이브리드 암호화 구현
- 부분 키 갱신을 통한 구독 기반 파일 접근 제어
- 구독 만료 시 프리미엄 콘텐츠 접근 제한

## 연구 활용 방안

- **IoT 기기 업데이트 관리**: 대규모 IoT 환경에서 기기별 맞춤형 업데이트 배포
- **구독 서비스 구현**: 차량, 가전제품 등의 구독 모델 서비스에 적용
- **접근 제어 강화**: 속성 기반의 세분화된 접근 제어로 보안 향상
- **오프라인 보안**: 네트워크 연결 없이도 속성 만료가 가능한 오프라인 보안 메커니즘
- **자원 효율성**: 부분 키 갱신을 통한 네트워크 및 계산 자원 절약
- **프라이버시 보호**: 개인 식별 없이 속성 기반으로 접근 권한 관리

## 시스템 구조

```
cp-abe/
├── cp_abe/                 # 핵심 CP-ABE 구현
│   ├── iot_cpabe.py        # 기본 CP-ABE 구현
│   ├── fading_function.py  # 페이딩 함수 기본 클래스
│   ├── fading_functions.py # 다양한 페이딩 함수 구현
│   ├── dynamic_cpabe.py    # 동적 속성 CP-ABE 구현
│   └── key_authority.py    # 키 관리 기관 구현
├── simulation.py           # 다양한 시뮬레이션 시나리오
├── car_subscription_simulation.py  # 자동차 구독 서비스 시뮬레이션
├── file_encryption.py      # 파일 암호화/복호화 데모
└── main.py                 # 기본 실행 스크립트
```
