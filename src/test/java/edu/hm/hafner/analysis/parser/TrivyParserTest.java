package edu.hm.hafner.analysis.parser;

import edu.hm.hafner.analysis.AbstractParserTest;
import edu.hm.hafner.analysis.IssueParser;
import edu.hm.hafner.analysis.Report;
import edu.hm.hafner.analysis.Severity;
import edu.hm.hafner.analysis.assertions.SoftAssertions;

/**
 * Tests the class {@link TrivyParser}.
 */
class TrivyParserTest extends AbstractParserTest {
    private static final String CATEGORY = DEFAULT_CATEGORY;

    protected TrivyParserTest() {
        super("trivy.json");
    }

    @Override
    protected IssueParser createParser() {
        return new TrivyParser();
    }

    @Override
    protected void assertThatIssuesArePresent(Report report, SoftAssertions softly) {
        softly.assertThat(report).hasSize(2);
        softly.assertThat(report.get(0))
                .hasFileName("ubuntu (ubuntu 20.04)")
                .hasMessage("bash: when effective UID is not equal to its real UID the saved UID is not dropped")
                .hasDescription("An issue was discovered in disable_priv_mode in shell.c in GNU Bash through 5.0 patch 11. By default, if Bash is run with its effective UID not equal "
                        + "to its real UID, it will drop privileges by setting its effective UID to its real UID. However, it does so incorrectly. On Linux and other systems "
                        + "that support \"saved UID\" functionality, the saved UID is not dropped. An attacker with command execution in the shell can use \"enable -f\" for runtime "
                        + "loading of a new builtin, which can be a shared object that calls setuid() and therefore regains privileges. However, binaries running with an effective "
                        + "UID of 0 are unaffected.")
                .hasSeverity(Severity.WARNING_LOW)
                .hasCategory("ubuntu")
                .hasType("CVE-2019-18276")
                .hasPackageName("bash");
        softly.assertThat(report.get(1))
                .hasFileName("ubuntu (ubuntu 20.04)")
                .hasMessage("coreutils: Non-privileged session can escape to the parent session in chroot")
                .hasDescription("chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes "
                        + "characters to the terminal's input buffer.")
                .hasSeverity(Severity.WARNING_LOW)
                .hasCategory("ubuntu")
                .hasType("CVE-2016-2781")
                .hasPackageName("coreutils");
    }
}