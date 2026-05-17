"""Tests for the unified LLM driver abstraction."""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from aiedge.llm_driver import (
    CodexCLIDriver,
    GeminiCLIDriver,
    LLMDriverResult,
    classify_llm_failure,
    resolve_driver,
)


class TestCodexCLIDriverAvailable:
    def test_available_when_codex_in_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex" if cmd == "codex" else None)
        driver = CodexCLIDriver()
        assert driver.available() is True

    def test_not_available_when_codex_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        driver = CodexCLIDriver()
        assert driver.available() is False


class TestCodexCLIDriverExecute:
    def test_success(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        fake_cp = subprocess.CompletedProcess(
            args=["codex", "exec"], returncode=0, stdout="output", stderr=""
        )
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: fake_cp)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "ok"
        assert result.stdout == "output"
        assert result.stderr == ""
        assert result.returncode == 0
        assert len(result.attempts) == 1

    def test_uses_workspace_write_and_run_local_codex_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        captured: dict[str, object] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="output", stderr=""
            )

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "ok"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert "-s" in cmd
        assert cmd[cmd.index("-s") + 1] == "workspace-write"
        assert "--add-dir" not in cmd
        env = captured["env"]
        assert isinstance(env, dict)
        assert env["CODEX_HOME"] == str(tmp_path / ".codex-home")
        assert (tmp_path / ".codex-home").is_dir()

    def test_respects_external_codex_home_with_add_dir(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        external_home = tmp_path.parent / "shared-codex-home"
        monkeypatch.setenv("CODEX_HOME", str(external_home))
        captured: dict[str, object] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["env"] = kwargs.get("env")
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="output", stderr=""
            )

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "ok"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert "--add-dir" in cmd
        assert cmd[cmd.index("--add-dir") + 1] == str(external_home)
        env = captured["env"]
        assert isinstance(env, dict)
        assert env["CODEX_HOME"] == str(external_home)
        assert external_home.is_dir()

    def test_seeds_default_auth_into_run_local_codex_home(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")
        monkeypatch.delenv("CODEX_HOME", raising=False)
        fake_home = tmp_path / "fake-home"
        monkeypatch.setenv("HOME", str(fake_home))
        source_auth = fake_home / ".codex" / "auth.json"
        source_auth.parent.mkdir(parents=True)
        source_auth.write_text('{"token":"abc"}', encoding="utf-8")

        def fake_run(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="output", stderr=""
            )

        monkeypatch.setattr("subprocess.run", fake_run)

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=run_dir,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "ok"
        target_auth = run_dir / ".codex-home" / "auth.json"
        assert target_auth.read_text(encoding="utf-8") == '{"token":"abc"}'

    def test_missing_cli(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: None)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
        )

        assert result.status == "missing_cli"
        assert result.returncode == -1
        assert "not found" in result.stderr

    def test_timeout(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        def fake_run(*args, **kwargs):
            raise subprocess.TimeoutExpired(cmd=["codex"], timeout=30.0)

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
        )

        assert result.status == "timeout"
        assert result.returncode == -1

    def test_file_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        def fake_run(*args, **kwargs):
            raise FileNotFoundError("codex not found")

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
        )

        assert result.status == "missing_cli"
        assert result.returncode == -1

    def test_retry_on_retryable_token(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        call_count = 0

        def fake_run(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return subprocess.CompletedProcess(
                    args=["codex"], returncode=1, stdout="", stderr="429 rate limited"
                )
            return subprocess.CompletedProcess(
                args=["codex"], returncode=0, stdout="success", stderr=""
            )

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=3,
            retryable_tokens=("429",),
        )

        assert result.status == "ok"
        assert result.stdout == "success"
        assert call_count == 2
        assert len(result.attempts) == 2

    def test_skip_git_repo_check_fallback(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        call_count = 0

        def fake_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if "--skip-git-repo-check" not in cmd:
                return subprocess.CompletedProcess(
                    args=cmd,
                    returncode=3,
                    stdout="",
                    stderr="Not inside a trusted directory and --skip-git-repo-check was not specified.",
                )
            return subprocess.CompletedProcess(
                args=cmd, returncode=0, stdout="OK", stderr=""
            )

        monkeypatch.setattr("subprocess.run", fake_run)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=3,
        )

        assert result.status == "ok"
        assert result.stdout == "OK"
        assert call_count == 2
        assert "--skip-git-repo-check" in result.argv

    def test_nonzero_exit_no_retry(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/codex")

        fake_cp = subprocess.CompletedProcess(
            args=["codex"], returncode=1, stdout="", stderr="some error"
        )
        monkeypatch.setattr("subprocess.run", lambda *a, **kw: fake_cp)

        driver = CodexCLIDriver()
        result = driver.execute(
            prompt="test prompt",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=3,
            retryable_tokens=("429",),
        )

        assert result.status == "nonzero_exit"
        assert result.returncode == 1
        assert len(result.attempts) == 1


class TestResolveDriver:
    def test_default_is_codex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AIEDGE_LLM_DRIVER", raising=False)
        driver = resolve_driver()
        assert isinstance(driver, CodexCLIDriver)
        assert driver.name == "codex"

    def test_explicit_codex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIEDGE_LLM_DRIVER", "codex")
        driver = resolve_driver()
        assert isinstance(driver, CodexCLIDriver)

    def test_explicit_gemini(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIEDGE_LLM_DRIVER", "gemini")
        driver = resolve_driver()
        assert isinstance(driver, GeminiCLIDriver)
        assert driver.name == "gemini"

    def test_unknown_falls_back_to_codex(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AIEDGE_LLM_DRIVER", "unknown_provider")
        driver = resolve_driver()
        assert isinstance(driver, CodexCLIDriver)


class TestLLMDriverResult:
    def test_frozen(self) -> None:
        result = LLMDriverResult(
            status="ok", stdout="out", stderr="", argv=[], attempts=[], returncode=0
        )
        with pytest.raises(AttributeError):
            result.status = "error"  # type: ignore[misc]


class TestGeminiCLIDriver:
    def test_available_when_gemini_in_path(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gemini" if cmd == "gemini" else None)
        assert GeminiCLIDriver().available() is True

    def test_not_available_when_gemini_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: None)
        assert GeminiCLIDriver().available() is False

    def test_success_uses_headless_text_mode_and_plan_approval(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gemini" if cmd == "gemini" else None)
        captured: dict[str, object] = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="gemini output", stderr="")

        monkeypatch.setattr("subprocess.run", fake_run)
        result = GeminiCLIDriver().execute(
            prompt="analyse firmware",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=1,
            system_prompt="Output JSON only.",
        )

        assert result.status == "ok"
        assert result.stdout == "gemini output"
        cmd = captured["cmd"]
        assert isinstance(cmd, list)
        assert cmd[:1] == ["gemini"]
        assert "--prompt" in cmd
        prompt_arg = cmd[cmd.index("--prompt") + 1]
        assert "[System instructions]" in prompt_arg
        assert "Output JSON only." in prompt_arg
        assert "analyse firmware" in prompt_arg
        assert "--output-format" in cmd
        assert cmd[cmd.index("--output-format") + 1] == "text"
        assert "--approval-mode" in cmd
        assert cmd[cmd.index("--approval-mode") + 1] == "plan"
        assert "--skip-trust" in cmd
        kwargs = captured["kwargs"]
        assert isinstance(kwargs, dict)
        assert kwargs.get("cwd") == str(tmp_path)

    def test_retries_on_rate_limit(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/gemini" if cmd == "gemini" else None)
        monkeypatch.setattr("time.sleep", lambda _seconds: None)
        call_count = 0

        def fake_run(cmd, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="429 rate", stderr="")
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="ok", stderr="")

        monkeypatch.setattr("subprocess.run", fake_run)
        result = GeminiCLIDriver().execute(
            prompt="test",
            run_dir=tmp_path,
            timeout_s=30.0,
            max_attempts=2,
        )

        assert result.status == "ok"
        assert call_count == 2
        assert len(result.attempts) == 2


class TestClassifyLlmFailure:
    def test_detects_quota_exhaustion_from_stdout(self) -> None:
        result = LLMDriverResult(
            status="nonzero_exit",
            stdout="You've hit your limit · resets 12am (Asia/Seoul)\n",
            stderr="",
            argv=["claude"],
            attempts=[],
            returncode=1,
        )
        assert classify_llm_failure(result)[0] == "quota_exhausted"

    def test_detects_driver_unavailable(self) -> None:
        result = LLMDriverResult(
            status="missing_cli",
            stdout="",
            stderr="claude executable not found",
            argv=["claude"],
            attempts=[],
            returncode=-1,
        )
        assert classify_llm_failure(result)[0] == "driver_unavailable"
