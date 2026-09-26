<div align="center">

# security-gate-public

**FINGU-GRINDA 공개(public) 레포 전용 보안 게이트: 시크릿 유출과 위험한 GitHub Actions 패턴을 PR 단계에서 막는다**

[![Required check](https://img.shields.io/badge/required%20check-org%20ruleset%2024047185-blue)](.github/workflows/public-gate.yml)
[![Runner](https://img.shields.io/badge/runner-GitHub--hosted%20ubuntu--latest-2ea44f)](#what-it-checks)
[![Secrets](https://img.shields.io/badge/secrets-none-success)](#what-it-checks)

[Why](#why) · [Checks](#what-it-checks) · [Fix](#remediation) · [Tests](#scenario-tests) · [Operations](#operations) · [Known gaps](#known-gaps)

</div>

---

조직의 기본 보안 게이트는 private 레포(`security-gate`)에 있다. 공개 레포는 그 게이트를 쓸 수 없어서, 이 레포의
`.github/workflows/public-gate.yml`(체크명 **`public-gate`**)이 org ruleset 으로 공개 레포 전체에 강제된다.

| | private 레포 | public 레포 |
|---|---|---|
| Ruleset | 20582782 (공개 레포는 exclude) | 24047185 `Security Gate · public repos` |
| Required workflow | private `security-gate` 워크플로 | `security-gate-public/.github/workflows/public-gate.yml@main` |
| 대상 브랜치 | 기본 브랜치 + `beta` | 기본 브랜치 + `refs/heads/beta` |
| Runner | self-hosted | GitHub-hosted `ubuntu-latest` |

## Why

- **GitHub 는 private 레포의 워크플로를 private 레포 안에서만 돌린다.** 공개 레포에 private 게이트를 required 로 걸면 체크가 영원히 뜨지 않는다.
- **self-hosted 러너 그룹은 공개 레포를 허용하지 않는다.** 허용하더라도 fork PR 코드를 내부 러너에서 돌리는 것은 안전하지 않다.
- 그래서 공개 레포는 시크릿 없이, 읽기 전용 토큰으로, GitHub-hosted 러너에서 가볍게 검사한다.

## What it checks

실행 환경: `ubuntu-latest`, 시크릿 없음, `permissions: contents: read`, 트리거는 `pull_request`·`push`·`merge_group`(`pull_request_target` 은 쓰지 않는다).

| Layer | Tool | BLOCK 조건 |
|---|---|---|
| secrets | gitleaks 8.28.0 (기본 룰, `--redact`) | PR·push·merge_group 커밋 범위 전체에서 시크릿 발견. 새 브랜치 push 와 merge_group 은 `origin/<default>..HEAD` 를 본다 |
| actions | YAML 파싱 검사 (`.github/workflows/*.yml`, `**/action.yml`) | 아래 3가지 패턴 |

actions 레이어가 막는 패턴(주석은 무시하고 파싱된 값만 본다):

1. **Template injection** — `run:` 또는 `with.script` 안에 공격자가 조작할 수 있는 표현식을 직접 넣음. 대상: `github.event.*`(issue, comment, pull_request, review, discussion, head_commit, commits, pages, workflow_run 의 head_branch 등), `github.head_ref`.
2. **`pull_request_target` + PR head checkout** — `pull_request_target` 트리거이면서 `head.sha`, `head.ref`, `refs/pull/`, `event.number` 등 PR head 를 참조.
3. **시크릿 전체 덤프** — `toJSON(secrets)` (대소문자 무시).

## Remediation

| 실패 | 조치 |
|---|---|
| Template injection | 값을 step 의 `env:` 로 옮기고 셸에서는 `"$VAR"` 로 참조한다 (아래 예시) |
| `pull_request_target` | `pull_request` 로 바꾸거나 PR head 를 checkout 하지 않는다 |
| `toJSON(secrets)` | 필요한 시크릿만 개별로 `env:` 에 넘긴다 |
| 시크릿 유출 | **키를 먼저 폐기(revoke)·재발급**한다. 히스토리 재작성은 선택 사항이다(공개 레포에 올라간 순간 이미 노출됐다고 본다) |

```yaml
# 나쁨: run 안에 PR 제목을 직접 치환 → 셸 인젝션
# 좋음:
- env:
    TITLE: <pull_request.title 표현식>
  run: echo "$TITLE"
```

## Scenario tests

2026-09-27, 13개 시나리오 전부 기대대로 동작 (수정 PR #1 `eb6a8ef` 이후).

| 결과 | 시나리오 |
|---|---|
| PASS | 깨끗한 변경, `.env.example` placeholder, `env:` + `"$VAR"` 패턴 |
| BLOCK | PAT 유출, AWS 키 유출, 과거 커밋(히스토리)에만 있는 유출 |
| BLOCK | template injection, `pull_request_target` + head checkout, `toJSON(secrets)` |
| 확인 | fork PR 은 읽기 전용 토큰·시크릿 없이 실행, private 레포는 영향 없음 |

## Operations

### 공개 레포 추가 / private → public 전환

**두 ruleset 모두** 고쳐야 한다. 24047185 에 include, 20582782 에 exclude. 한쪽만 하면 private 게이트 체크가 영원히 뜨지 않아 **PR 이 계속 BLOCKED** 된다.

```bash
ORG=FINGU-GRINDA; REPO=new-public-repo
KEEP='{name,target,enforcement,conditions,rules,bypass_actors}'

# public ruleset: include 에 추가
gh api orgs/$ORG/rulesets/24047185 --jq "$KEEP" \
  | jq --arg r "$REPO" '.conditions.repository_name.include += [$r] | .conditions.repository_name.include |= unique' \
  | gh api -X PUT orgs/$ORG/rulesets/24047185 --input -

# private ruleset: exclude 에 추가
gh api orgs/$ORG/rulesets/20582782 --jq "$KEEP" \
  | jq --arg r "$REPO" '.conditions.repository_name.exclude += [$r] | .conditions.repository_name.exclude |= unique' \
  | gh api -X PUT orgs/$ORG/rulesets/20582782 --input -

# 확인
gh api orgs/$ORG/rulesets/24047185 --jq .conditions.repository_name
gh api orgs/$ORG/rulesets/20582782 --jq .conditions.repository_name
```

ruleset 을 고치기 전 JSON 백업은 조직 관리자가 보관한다. public → private 전환은 위를 반대로 한다.

### public-gate 자체를 고칠 때

이 레포의 PR 도 `main` 에 있는 public-gate 로 검사된다. 그래서 게이트 버그를 고치는 PR 이 그 버그 때문에 막힐 수 있다(self-block).

- **권장**: ruleset 24047185 에 조직 관리자 bypass actor 를 둔다(현재 없음).
- **2026-09-27 에 쓴 임시 절차**: ① ruleset 백업 → ② 24047185 include 에서 `security-gate-public` 을 잠시 제외 → ③ 수정 PR 머지 → ④ 즉시 다시 include 하고 조건을 확인한다. 제외 시간은 최소로 한다.

## Known gaps

- 공개 레포 `main` 에 대한 push 스캔은 따로 없다. 직접 push 는 ruleset 이 막는 것으로 보지만 검증하지 않았다.
- 첫 기여자의 fork PR 은 관리자가 승인해야 게이트가 돈다.
- gitleaks 기본 룰만 쓴다(커스텀 룰 없음).
- injection 검사는 패턴 기반이다. `inputs.*`, reusable workflow, 외부 action 내부는 보지 않는다.
- `actions/checkout@v4` 에서 Node 20 deprecation 경고가 나온다.
