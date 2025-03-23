# CP-ABE와 기존 방식의 알고리즘 수식 정리

## I. 시스템 설정 (Setup)

**기존 방식:**
$$\text{Setup}_{\text{trad}}() \rightarrow (\text{PK}, \text{SK})$$
- 각 기기마다 개별 대칭키 생성

**CP-ABE 방식:**
$$\text{Setup}_{\text{cpabe}}() \rightarrow (\text{PK}, \text{MSK}, \mathcal{FF})$$
여기서:
- PK: 공개 파라미터
- MSK: 마스터 비밀키
- $\mathcal{FF}$: 페이딩 함수 집합 $\{f_{\text{attr}}: \text{attr} \in \mathcal{A}\}$

## II. 키 생성 (KeyGen)

**기존 방식:**
$$\text{KeyGen}_{\text{trad}}(\text{device\_id}) \rightarrow K_{\text{device\_id}}$$

**CP-ABE 방식:**
$$\text{KeyGen}_{\text{cpabe}}(\text{MSK}, S) \rightarrow \text{SK}_S$$
여기서:
- $S \subset \mathcal{A}$: 사용자 속성 집합
- $\text{SK}_S$: 속성 집합 $S$에 해당하는 비밀키

## III. 동적 속성 키 생성 (DynamicKeyGen)

$$\text{DynamicKeyGen}(\text{MSK}, S_{\text{static}}, S_{\text{dynamic}}) \rightarrow \text{SK}_{S_{\text{static}} \cup S_{\text{dynamic}}(t)}$$
여기서:
- $S_{\text{static}}$: 정적 속성 집합 (모델, 지역 등)
- $S_{\text{dynamic}}$: 동적 속성 집합 (구독 등)
- $S_{\text{dynamic}}(t)$: 시간 $t$에서의 동적 속성 값 = $\{f_{\text{attr}}(t) : \text{attr} \in S_{\text{dynamic}}\}$

## IV. 암호화 (Encrypt)

**기존 방식:**
$$\text{Encrypt}_{\text{trad}}(m, \{K_{\text{device\_id}}\}) \rightarrow \{\text{CT}_{\text{device\_id}}\}$$

**CP-ABE 방식:**
$$\text{Encrypt}_{\text{cpabe}}(\text{PK}, m, \mathcal{P}) \rightarrow \text{CT}_{\mathcal{P}}$$
여기서:
- $m$: 메시지 (업데이트 내용)
- $\mathcal{P}$: 접근 구조 (정책)
- $\text{CT}_{\mathcal{P}}$: 정책 $\mathcal{P}$에 따라 암호화된 암호문

## V. 복호화 (Decrypt)

**기존 방식:**
$$\text{Decrypt}_{\text{trad}}(\text{CT}_{\text{device\_id}}, K_{\text{device\_id}}) \rightarrow m$$

**CP-ABE 방식:**
$$\text{Decrypt}_{\text{cpabe}}(\text{PK}, \text{CT}_{\mathcal{P}}, \text{SK}_S) \rightarrow \begin{cases}
m & \text{if}\ S\ \text{satisfies}\ \mathcal{P}\ \text{at time}\ t \\
\perp & \text{otherwise}
\end{cases}$$
- $S$가 $\mathcal{P}$를 만족하는 경우에만 성공

## VI. 속성 갱신 (UpdateAttribute)

$$\text{UpdateAttribute}(\text{MSK}, \text{user\_id}, \text{attr}) \rightarrow \text{SK}_{\text{attr}}^{\text{new}}$$
여기서:
- $\text{attr}$: 갱신할 속성
- $\text{SK}_{\text{attr}}^{\text{new}}$: 해당 속성의 새 키 구성요소

## VII. 키 병합 (MergeKey)

$$\text{MergeKey}(\text{SK}_S, \text{SK}_{\text{attr}}^{\text{new}}) \rightarrow \text{SK}_{S'}$$
여기서:
- $S' = (S \setminus \{\text{attr}\}) \cup \{\text{attr}^{\text{new}}\}$

## VIII. 페이딩 함수 (Fading Function)

$$f_{\text{attr}}(t) = \text{attr} \| \lfloor (t - t_{\text{base}}) / \text{lifetime} \rfloor$$
여기서:
- $t$: 현재 시간
- $t_{\text{base}}$: 기준 시간
- $\text{lifetime}$: 속성 수명

## IX. 접근 취소 (RevokeAccess)

**기존 방식:**
$$\text{RevokeAccess}_{\text{trad}}(\text{device\_id}) \rightarrow \{\text{new\_keys}_i\}_{i \neq \text{device\_id}} \text{ and } \{\text{re-encrypted\_updates}\}$$

**CP-ABE 방식:**
$$\text{RevokeAccess}_{\text{cpabe}}(\text{device\_id}) \rightarrow \text{BlackList} \cup \{\text{device\_id}\}$$
