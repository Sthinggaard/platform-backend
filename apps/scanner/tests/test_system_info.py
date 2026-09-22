from unittest.mock import patch

from scanner_agent import system_info
from scanner_agent.system_info import detect_architecture, detect_os


def test_detect_architecture_returns_platform_machine():
    with patch("platform.machine", return_value="x86_64"):
        assert detect_architecture() == "x86_64"


def test_detect_architecture_falls_back_to_unknown_when_empty():
    with patch("platform.machine", return_value=""):
        assert detect_architecture() == "unknown"


def test_detect_os_prefers_os_release_on_linux(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Ubuntu"\nVERSION_ID="22.04"\nID=ubuntu\n')

    with (
        patch("platform.system", return_value="Linux"),
        patch("scanner_agent.system_info._OS_RELEASE_PATH", os_release),
    ):
        assert detect_os() == ("Ubuntu", "22.04")


def test_detect_os_falls_back_when_os_release_missing(tmp_path):
    missing = tmp_path / "does-not-exist"

    with (
        patch("platform.system", return_value="Linux"),
        patch("platform.release", return_value="6.8.0"),
        patch("scanner_agent.system_info._OS_RELEASE_PATH", missing),
    ):
        assert detect_os() == ("Linux", "6.8.0")


def test_detect_os_falls_back_when_os_release_has_no_name(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('VERSION_ID="22.04"\n')

    with (
        patch("platform.system", return_value="Linux"),
        patch("platform.release", return_value="6.8.0"),
        patch("scanner_agent.system_info._OS_RELEASE_PATH", os_release),
    ):
        assert detect_os() == ("Linux", "6.8.0")


def test_detect_os_uses_platform_fallback_on_non_linux():
    with (
        patch("platform.system", return_value="Darwin"),
        patch("platform.release", return_value="23.1.0"),
    ):
        assert detect_os() == ("Darwin", "23.1.0")


def test_detect_os_handles_missing_version_id(tmp_path):
    os_release = tmp_path / "os-release"
    os_release.write_text('NAME="Alpine Linux"\n')

    with (
        patch("platform.system", return_value="Linux"),
        patch("scanner_agent.system_info._OS_RELEASE_PATH", os_release),
    ):
        assert detect_os() == ("Alpine Linux", "")


class TestHostIdentityDoesNotClaimWhatItCannotSee:
    """CA-02.3 slice 3.

    `detect_os()` reads /etc/os-release, which inside a container describes the
    *image*. The platform stored that as the machine's OS with nothing recording
    which it was. On Søren's Pi it read "Debian GNU/Linux" — also what the host
    runs — so it looked correct; on an Ubuntu host running the same image it
    would simply have been wrong, and nothing downstream could have told.
    """

    def test_a_containerised_collector_does_not_report_the_image_as_the_host_os(self, monkeypatch):
        monkeypatch.setattr(system_info, "detect_container_runtime", lambda: "docker")
        monkeypatch.setattr(system_info, "_read_os_release", lambda: ("Debian GNU/Linux", "12"))
        monkeypatch.setattr(system_info.platform, "system", lambda: "Linux")

        identity = system_info.describe_host()

        # The regression: this used to be reported as the machine's OS.
        assert identity.distribution_name is None
        # Not discarded either — kept where it is true.
        assert identity.runtime_distribution_name == "Debian GNU/Linux"
        assert identity.container_runtime == "docker"

    def test_a_native_collector_does_report_the_host_os(self, monkeypatch):
        monkeypatch.setattr(system_info, "detect_container_runtime", lambda: None)
        monkeypatch.setattr(system_info, "_read_os_release", lambda: ("Ubuntu", "24.04"))
        monkeypatch.setattr(system_info.platform, "system", lambda: "Linux")

        identity = system_info.describe_host()

        assert identity.distribution_name == "Ubuntu"
        assert identity.distribution_version == "24.04"
        assert identity.runtime_distribution_name is None
        assert identity.is_containerised is False

    def test_kernel_and_architecture_are_reported_even_inside_a_container(self, monkeypatch):
        # These genuinely are host facts — containers share the kernel.
        # Verified on the real Pi: platform.release() inside the container is
        # byte-identical to the host's `uname -r`.
        monkeypatch.setattr(system_info, "detect_container_runtime", lambda: "docker")
        monkeypatch.setattr(system_info.platform, "release", lambda: "6.18.34+rpt-rpi-v8")
        monkeypatch.setattr(system_info.platform, "machine", lambda: "aarch64")

        identity = system_info.describe_host()

        assert identity.kernel_release == "6.18.34+rpt-rpi-v8"
        assert identity.architecture == "aarch64"


class TestContainerDetection:
    def test_dockerenv_marks_a_container(self, monkeypatch, tmp_path):
        marker = tmp_path / ".dockerenv"
        marker.write_text("")
        monkeypatch.setattr(system_info, "_DOCKER_ENV_PATH", marker)

        assert system_info.detect_container_runtime() == "docker"

    def test_cgroup_is_a_second_signal_when_dockerenv_is_absent(self, monkeypatch, tmp_path):
        # /.dockerenv is absent under podman and some rootless setups. A false
        # negative is the dangerous direction: it would let the image's
        # os-release be reported as the machine's OS.
        monkeypatch.setattr(system_info, "_DOCKER_ENV_PATH", tmp_path / "absent")
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("0::/kubepods/besteffort/pod123/abc\n")
        monkeypatch.setattr(system_info, "_CGROUP_PATH", cgroup)

        assert system_info.detect_container_runtime() == "kubepods"

    def test_a_plain_host_is_not_reported_as_a_container(self, monkeypatch, tmp_path):
        monkeypatch.setattr(system_info, "_DOCKER_ENV_PATH", tmp_path / "absent")
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("0::/init.scope\n")
        monkeypatch.setattr(system_info, "_CGROUP_PATH", cgroup)

        assert system_info.detect_container_runtime() is None

    def test_an_unreadable_cgroup_does_not_crash_the_agent(self, monkeypatch, tmp_path):
        monkeypatch.setattr(system_info, "_DOCKER_ENV_PATH", tmp_path / "absent")
        monkeypatch.setattr(system_info, "_CGROUP_PATH", tmp_path / "missing")

        assert system_info.detect_container_runtime() is None
