# Homebrew formula for the Authio CLI.
#
# This is the in-repo template for the formula that lives in the tap
# (homebrew-tap). The release workflow (.github/workflows/release.yml)
# regenerates the `version`, `url`, and `sha256` fields from each tagged
# release's checksums file and opens a bump PR against the tap, so the
# placeholders below are filled automatically — do not hand-edit the
# pinned values.
#
#   brew install authio-com/tap/authio
#
class Authio < Formula
  desc "Official Authio CLI — login, doctor, env, and local webhook forwarding"
  homepage "https://github.com/authio-com/authio_cli"
  version "0.0.0" # x-release-please-version
  license "MIT"

  BASE = "https://github.com/authio-com/authio_cli/releases/download".freeze

  on_macos do
    on_arm do
      url "#{BASE}/v#{version}/authio_#{version}_darwin_arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{BASE}/v#{version}/authio_#{version}_darwin_amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  on_linux do
    on_arm do
      url "#{BASE}/v#{version}/authio_#{version}_linux_arm64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
    on_intel do
      url "#{BASE}/v#{version}/authio_#{version}_linux_amd64.tar.gz"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000"
    end
  end

  def install
    bin.install "authio"
  end

  test do
    assert_match "authio", shell_output("#{bin}/authio version")
  end
end
