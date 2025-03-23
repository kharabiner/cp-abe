# CP-ABE와 기존 방식의 알고리즘 수식 정리

## I. 시스템 설정 (Setup)

**기존 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Setup}_{\text{trad}}()%20\rightarrow%20(\text{PK},%20\text{SK}))
- 각 기기마다 개별 대칭키 생성

**CP-ABE 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Setup}_{\text{cpabe}}()%20\rightarrow%20(\text{PK},%20\text{MSK},%20\mathcal{FF}))
여기서:
- PK: 공개 파라미터
- MSK: 마스터 비밀키
- ![equation](https://latex.codecogs.com/png.latex?\mathcal{FF}): 페이딩 함수 집합 ![equation](https://latex.codecogs.com/png.latex?\{f_{\text{attr}}:%20\text{attr}%20\in%20\mathcal{A}\})

## II. 키 생성 (KeyGen)

**기존 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{KeyGen}_{\text{trad}}(\text{device\_id})%20\rightarrow%20K_{\text{device\_id}})

**CP-ABE 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{KeyGen}_{\text{cpabe}}(\text{MSK},%20S)%20\rightarrow%20\text{SK}_S)
여기서:
- ![equation](https://latex.codecogs.com/png.latex?S%20\subset%20\mathcal{A}): 사용자 속성 집합
- ![equation](https://latex.codecogs.com/png.latex?\text{SK}_S): 속성 집합 S에 해당하는 비밀키

## III. 동적 속성 키 생성 (DynamicKeyGen)

![equation](https://latex.codecogs.com/png.latex?\text{DynamicKeyGen}(\text{MSK},%20S_{\text{static}},%20S_{\text{dynamic}})%20\rightarrow%20\text{SK}_{S_{\text{static}}%20\cup%20S_{\text{dynamic}}(t)})
여기서:
- ![equation](https://latex.codecogs.com/png.latex?S_{\text{static}}): 정적 속성 집합 (모델, 지역 등)
- ![equation](https://latex.codecogs.com/png.latex?S_{\text{dynamic}}): 동적 속성 집합 (구독 등)
- ![equation](https://latex.codecogs.com/png.latex?S_{\text{dynamic}}(t)): 시간 t에서의 동적 속성 값 = ![equation](https://latex.codecogs.com/png.latex?\{f_{\text{attr}}(t)%20:%20\text{attr}%20\in%20S_{\text{dynamic}}\})

## IV. 암호화 (Encrypt)

**기존 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Encrypt}_{\text{trad}}(m,%20\{K_{\text{device\_id}}\})%20\rightarrow%20\{\text{CT}_{\text{device\_id}}\})

**CP-ABE 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Encrypt}_{\text{cpabe}}(\text{PK},%20m,%20\mathcal{P})%20\rightarrow%20\text{CT}_\mathcal{P})
여기서:
- m: 메시지 (업데이트 내용)
- ![equation](https://latex.codecogs.com/png.latex?\mathcal{P}): 접근 구조 (정책)
- ![equation](https://latex.codecogs.com/png.latex?\text{CT}_\mathcal{P}): 정책 ![equation](https://latex.codecogs.com/png.latex?\mathcal{P})에 따라 암호화된 암호문

## V. 복호화 (Decrypt)

**기존 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Decrypt}_{\text{trad}}(\text{CT}_{\text{device\_id}},%20K_{\text{device\_id}})%20\rightarrow%20m)

**CP-ABE 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{Decrypt}_{\text{cpabe}}(\text{PK},%20\text{CT}_\mathcal{P},%20\text{SK}_S)%20\rightarrow%20\begin{cases}m%20&%20\text{if}%20S%20\text{satisfies}%20\mathcal{P}%20\text{at%20time}%20t%20\\\perp%20&%20\text{otherwise}\end{cases})

- S가 ![equation](https://latex.codecogs.com/png.latex?\mathcal{P})를 만족하는 경우에만 성공

## VI. 속성 갱신 (UpdateAttribute)

![equation](https://latex.codecogs.com/png.latex?\text{UpdateAttribute}(\text{MSK},%20\text{user\_id},%20\text{attr})%20\rightarrow%20\text{SK}_{\text{attr}}^{\text{new}})
여기서:
- attr: 갱신할 속성
- ![equation](https://latex.codecogs.com/png.latex?\text{SK}_{\text{attr}}^{\text{new}}): 해당 속성의 새 키 구성요소

## VII. 키 병합 (MergeKey)

![equation](https://latex.codecogs.com/png.latex?\text{MergeKey}(\text{SK}_S,%20\text{SK}_{\text{attr}}^{\text{new}})%20\rightarrow%20\text{SK}_{S'})
여기서:
- ![equation](https://latex.codecogs.com/png.latex?S'%20=%20(S%20\setminus%20\{\text{attr}\})%20\cup%20\{\text{attr}^{\text{new}}\})

## VIII. 페이딩 함수 (Fading Function)

![equation](https://latex.codecogs.com/png.latex?f_{\text{attr}}(t)%20=%20\text{attr}%20\|%20\lfloor%20(t%20-%20t_{\text{base}})%20/%20\text{lifetime}%20\rfloor)
여기서:
- t: 현재 시간
- ![equation](https://latex.codecogs.com/png.latex?t_{\text{base}}): 기준 시간
- lifetime: 속성 수명

## IX. 접근 취소 (RevokeAccess)

**기존 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{RevokeAccess}_{\text{trad}}(\text{device\_id})%20\rightarrow%20\{\text{new\_keys}_i\}_{i%20\neq%20\text{device\_id}}%20\text{%20and%20}%20\{\text{re-encrypted\_updates}\})

**CP-ABE 방식:**
![equation](https://latex.codecogs.com/png.latex?\text{RevokeAccess}_{\text{cpabe}}(\text{device\_id})%20\rightarrow%20\text{BlackList}%20\cup%20\{\text{device\_id}\})
