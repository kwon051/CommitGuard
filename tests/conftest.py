"""국내 규칙 테스트 결과를 공유용 샘플로 내보내는 선택 옵션."""


def pytest_addoption(parser):
    parser.addoption(
        "--kr-report-dir",
        metavar="DIR",
        default=None,
        help="기본 국내 규칙 예시 40건의 가린 원본·finding JSON 저장 폴더",
    )
