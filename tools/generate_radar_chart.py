import os
import matplotlib.pyplot as plt
import numpy as np
import matplotlib

# GUI 없이 실행하기 위한 백엔드 설정
matplotlib.use("Agg")

# 결과 저장 경로 설정
parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
output_dir = os.path.join(parent_dir, "experiment_results")
os.makedirs(output_dir, exist_ok=True)

# 폰트 설정
plt.rcParams["font.family"] = "DejaVu Sans"
plt.rcParams["axes.unicode_minus"] = False


def generate_radar_chart():
    """시스템 비교를 위한 레이더 차트 생성"""

    # 카테고리와 데이터 정의 - 영어로 변경하되 간결하게
    categories = [
        "Scalability",
        "Bandwidth\nEfficiency",
        "Access Control\nFlexibility",
        "Offline\nSecurity",
        "Key Update\nEfficiency",
        "Key Size\nEfficiency",
        "Implementation\nEase",
    ]

    # 7개의 측정 항목에 1-5 척도로 점수 부여
    # [기존 방식, 제안 방식]
    values = [
        [2, 5],  # 확장성
        [1, 5],  # 대역폭 효율성
        [2, 5],  # 접근 제어 유연성
        [1, 4],  # 오프라인 보안
        [2, 5],  # 키 갱신 효율성
        [4, 2],  # 키 크기 효율성 (CP-ABE는 키가 큼)
        [5, 3],  # 구현 용이성 (CP-ABE는 구현이 더 복잡함)
    ]

    # 값 준비
    values_traditional = [v[0] for v in values]
    values_proposed = [v[1] for v in values]

    # 카테고리 수
    N = len(categories)

    # 각도 계산
    angles = [n / float(N) * 2 * np.pi for n in range(N)]
    angles += angles[:1]  # 그래프를 완성하기 위해 첫 포인트 반복

    # 값 배열 확장
    values_traditional += values_traditional[:1]
    values_proposed += values_proposed[:1]

    # 그래프 설정 - 크기 증가 및 여백 확보
    fig, ax = plt.subplots(figsize=(14, 12), subplot_kw=dict(polar=True))

    # 기존 방식 그래프
    ax.plot(angles, values_traditional, "o-", linewidth=2, label="Traditional")
    ax.fill(angles, values_traditional, alpha=0.25)

    # 제안 방식 그래프 - 레이블 간소화
    ax.plot(
        angles,
        values_proposed,
        "o-",
        linewidth=2,
        label="CP-ABE + Fading Function + Partial Key",
    )
    ax.fill(angles, values_proposed, alpha=0.25)

    # 틱과 레이블 설정 - 텍스트 크기 조정 및 줄바꿈 처리
    ax.set_thetagrids(np.array(angles[:-1]) * 180 / np.pi, categories)
    ax.set_ylim(0, 5)
    ax.set_yticks([1, 2, 3, 4, 5])
    ax.set_yticklabels(["1", "2", "3", "4", "5"])

    # 레이블 폰트 크기 조정
    for label in ax.get_xticklabels():
        label.set_fontsize(9)

    # 제목 및 범례 - 범례 위치 조정
    plt.title("System Performance Comparison", size=16, y=1.1)

    # 범례를 그래프 밖 오른쪽에 배치
    plt.legend(loc="center left", bbox_to_anchor=(1.25, 0.5), fontsize=10)

    # 더 넓은 여백 설정
    plt.subplots_adjust(right=0.7)

    # 저장 - 여백 고려
    output_path = os.path.join(output_dir, "system_comparison_radar.png")
    plt.savefig(output_path, bbox_inches="tight", pad_inches=0.5)
    print(f"Radar chart saved: {output_path}")


if __name__ == "__main__":
    generate_radar_chart()
