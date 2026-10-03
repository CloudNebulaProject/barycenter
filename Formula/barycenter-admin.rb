class BarycenterAdmin < Formula
  desc "Email Barycenter invitations and password reset links"
  homepage "https://github.com/CloudNebulaProject/barycenter"
  head "https://github.com/CloudNebulaProject/barycenter.git", branch: "main"
  license any_of: ["MIT", "Apache-2.0"]
  depends_on "python@3.14"

  def install
    bin.install "cli/barycenter-admin"
    inreplace bin/"barycenter-admin", "#!/usr/bin/env python3", "#!#{Formula["python@3.14"].opt_bin}/python3.14"
  end

  test do
    assert_match "invite", shell_output("#{bin}/barycenter-admin --help")
  end
end
