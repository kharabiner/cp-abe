# CP-ABE 기반 IoT 소프트웨어 업데이트 프레임워크

본 프로젝트는 CP-ABE(Ciphertext-Policy Attribute-Based Encryption), Fading Function, 부분 키 갱신 기술을 활용한 IoT 소프트웨어 업데이트 프레임워크를 구현합니다.

## 주요 기능

1. **속성 기반 암호화(CP-ABE)**: 
   - **정적 속성**: 모델(model), 일련번호(serialNumber) 기반 접근 제어
   - **동적 속성**: 구독(subscription), 보증(warranty) 등 시간에 따라 변하는 속성 관리
2. **Fading Function**: 구독 기한과 보증 기간 같은 시간 제한 속성이 자동으로 만료되는 기능
3. **부분 키 갱신**: 만료된 키를 전체가 아닌 필요한 부분(구독, 보증)만 갱신

## 테스트 시나리오 실행

```bash
# 도커 이미지 빌드
docker-compose build

# 테스트 시나리오 실행
docker-compose run cp-abe python test/stage1_basic_encryption.py
docker-compose run cp-abe python test/stage2_dynamic_attributes.py
docker-compose run cp-abe python test/stage3_key_authority.py
docker-compose run cp-abe python test/stage4_real_world_scenarios.py

# 실험 및 성능 평가
docker-compose run cp-abe python test/update_approach_comparison.py
```

## 테스트 시나리오 단계

### 1단계: 기본 CP-ABE 설정 및 암호화/복호화 (stage1_basic_encryption.py)
- 기본 CP-ABE 시스템 초기화
- 키 생성 및 정책 기반 암호화/복호화
- 파일 암호화/복호화 하이브리드 접근법 (AES+CP-ABE)

### 2단계: 동적 속성 테스트 (stage2_dynamic_attributes.py)
- 페이딩 함수 등록 및 사용
- 만료되는 구독/보증 속성 테스트
- 부분 키 갱신 메커니즘 검증
- 실시간 속성 변경 모니터링

### 3단계: 키 인증 기관 테스트 (stage3_key_authority.py)
- 기기 등록 및 키 발급
- 구독 및 보증 갱신 정책 설정
- 기기 접근 취소 메커니즘
- 갱신 제한 및 블랙리스트 테스트

### 4단계: 실제 응용 시나리오 (stage4_real_world_scenarios.py)
- 차량 구독 서비스 시뮬레이션
- 다수 IoT 기기 확장성 테스트
- 오프라인 만료 검증
- 정책 변경 및 속성 추적

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
│   ├── fading_functions.py # 다양한 페이딩 함수 구현
│   ├── dynamic_cpabe.py    # 동적 속성 CP-ABE 구현
│   └── key_authority.py    # 키 관리 기관 구현
├── test/
│   ├── stage1_basic_encryption.py  # 기본 CP-ABE 설정 및 암호화/복호화
│   ├── stage2_dynamic_attributes.py  # 동적 속성 테스트
│   ├── stage3_key_authority.py  # 키 인증 기관 테스트
│   ├── stage4_real_world_scenarios.py  # 실제 응용 시나리오
│   ├── update_approach_comparison.py  # 실험 및 성능 평가
└── main.py                 # 기본 실행 스크립트
```
