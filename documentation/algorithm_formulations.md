# CP-ABE와 기존 방식의 알고리즘 수식 정리

## I. 시스템 설정 (Setup)

**기존 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Setup_{trad}()%20\rightarrow%20(PK,%20SK)" alt="Setup_trad() -> (PK, SK)">
- 각 기기마다 개별 대칭키 생성

**CP-ABE 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Setup_{cpabe}()%20\rightarrow%20(PK,%20MSK,%20\mathcal{FF})" alt="Setup_cpabe() -> (PK, MSK, FF)">
여기서:
- PK: 공개 파라미터
- MSK: 마스터 비밀키
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\mathcal{FF}" alt="FF">: 페이딩 함수 집합 <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\{f_{attr}:%20attr%20\in%20\mathcal{A}\}" alt="f_attr: attr in A">

## II. 키 생성 (KeyGen)

**기존 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}KeyGen_{trad}(device\_id)%20\rightarrow%20K_{device\_id}" alt="KeyGen_trad(device_id) -> K_device_id">

**CP-ABE 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}KeyGen_{cpabe}(MSK,%20S)%20\rightarrow%20SK_S" alt="KeyGen_cpabe(MSK, S) -> SK_S">
여기서:
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}S%20\subset%20\mathcal{A}" alt="S subset A">: 사용자 속성 집합
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}SK_S" alt="SK_S">: 속성 집합 S에 해당하는 비밀키

## III. 동적 속성 키 생성 (DynamicKeyGen)

<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}DynamicKeyGen(MSK,%20S_{static},%20S_{dynamic})%20\rightarrow%20SK_{S_{static}%20\cup%20S_{dynamic}(t)}" alt="DynamicKeyGen">
여기서:
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}S_{static}" alt="S_static">: 정적 속성 집합 (모델, 일련번호)
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}S_{dynamic}" alt="S_dynamic">: 동적 속성 집합 (구독, 보증)
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}S_{dynamic}(t)" alt="S_dynamic(t)">: 시간 t에서의 동적 속성 값 = <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\{f_{attr}(t)%20:%20attr%20\in%20S_{dynamic}\}" alt="dynamic attrs">

## IV. 암호화 (Encrypt)

**기존 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Encrypt_{trad}(m,%20\{K_{device\_id}\})%20\rightarrow%20\{CT_{device\_id}\}" alt="Encrypt_trad">

**CP-ABE 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Encrypt_{cpabe}(PK,%20m,%20\mathcal{P})%20\rightarrow%20CT_\mathcal{P}" alt="Encrypt_cpabe">
여기서:
- m: 메시지 (업데이트 내용)
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\mathcal{P}" alt="P">: 접근 구조 (정책)
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}CT_\mathcal{P}" alt="CT_P">: 정책 <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\mathcal{P}" alt="P">에 따라 암호화된 암호문

## V. 복호화 (Decrypt)

**기존 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Decrypt_{trad}(CT_{device\_id},%20K_{device\_id})%20\rightarrow%20m" alt="Decrypt_trad">

**CP-ABE 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}Decrypt_{cpabe}(PK,%20CT_\mathcal{P},%20SK_S)%20\rightarrow%20\begin{cases}m%20&%20if%20S%20satisfies%20\mathcal{P}%20at%20time%20t%20\\\perp%20&%20otherwise\end{cases}" alt="Decrypt_cpabe">

- S가 <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}\mathcal{P}" alt="P">를 만족하는 경우에만 성공

## VI. 속성 갱신 (UpdateAttribute)

<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}UpdateAttribute(MSK,%20user\_id,%20attr)%20\rightarrow%20SK_{attr}^{new}" alt="UpdateAttribute">
여기서:
- attr: 갱신할 속성
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}SK_{attr}^{new}" alt="SK_attr^new">: 해당 속성의 새 키 구성요소

## VII. 키 병합 (MergeKey)

<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}MergeKey(SK_S,%20SK_{attr}^{new})%20\rightarrow%20SK_{S'}" alt="MergeKey">
여기서:
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}S'%20=%20(S%20\setminus%20\{attr\})%20\cup%20\{attr^{new}\}" alt="S_prime">

## VIII. 페이딩 함수 (Fading Function)

구독 속성을 위한 페이딩 함수:
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}f_{subscription}(t)%20=%20subscription%20\|%20\lfloor%20(t%20-%20t_{base})%20/%20lifetime%20\rfloor" alt="subscription fading function">

보증 속성을 위한 페이딩 함수:
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}f_{warranty}(t)%20=%20warranty%20\|%20\lfloor%20(t%20-%20t_{base})%20/%20lifetime%20\rfloor" alt="warranty fading function">

여기서:
- t: 현재 시간
- <img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}t_{base}" alt="t_base">: 기준 시간
- lifetime: 속성 수명

## IX. 접근 취소 (RevokeAccess)

**기존 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}RevokeAccess_{trad}(device\_id)%20\rightarrow%20\{new\_keys_i\}_{i%20\neq%20device\_id}%20and%20\{re-encrypted\_updates\}" alt="RevokeAccess_trad">

**CP-ABE 방식:**
<img src="https://latex.codecogs.com/png.image?\dpi{110}\bg{white}RevokeAccess_{cpabe}(device\_id)%20\rightarrow%20BlackList%20\cup%20\{device\_id\}" alt="RevokeAccess_cpabe">
