# {package}를 {recommended_version}으로 올리면 취약점 {fixed_count}개 해결

**무엇이 발견됐나요?**
`{file}`의 {package} {current_version} 버전에서 취약점 {fixed_count}개가 발견됐습니다. (가장 높은 위험도: {max_severity})
관련 취약점: {cves}

**왜 위험한가요?**
같은 패키지에 취약점이 여러 개 쌓여 있으면 공격받을 수 있는 경로도 그만큼 많아집니다.

**어떻게 고치나요?**
1. `{file}`에서 {package} 버전을 {recommended_version}으로 올립니다. 이것만으로 {fixed_count}개가 함께 해결됩니다.
2. 큰 버전 업그레이드(예: 1.x → 2.x)라면 사용하던 기능이 바뀌었을 수 있으니 꼭 실행해서 확인합니다.
3. 다시 검사해서 해결됐는지 확인합니다.