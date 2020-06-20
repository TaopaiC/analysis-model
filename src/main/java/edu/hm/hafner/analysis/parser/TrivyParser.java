package edu.hm.hafner.analysis.parser;

import edu.hm.hafner.analysis.Issue;
import edu.hm.hafner.analysis.IssueBuilder;
import edu.hm.hafner.analysis.IssueParser;
import edu.hm.hafner.analysis.ParsingException;
import edu.hm.hafner.analysis.ReaderFactory;
import edu.hm.hafner.analysis.Report;
import edu.hm.hafner.analysis.Severity;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import java.io.IOException;
import java.io.Reader;

/**
 * A parser for Trivy warnings.
 *
 * @author PCTao
 */
public class TrivyParser extends IssueParser {
    private static final long serialVersionUID = 23797345723423458L;

    /** The issue array. */
    private static final String REPORT_ISSUES = "Vulnerabilities";
    /** fileName. */
    private static final String REPORT_TARGET = "Target";
    /** category. */
    private static final String REPORT_TYPE = "Type";

    /** issue.Severity attribute. */
    private static final String ISSUE_SEVERITY = "Severity";
    /** issue.PkgName attribute. */
    private static final String ISSUE_PKGNAME = "PkgName";
    /** issue.Type attribute. */
    private static final String ISSUE_TYPE = "VulnerabilityID";
    /** issue.Title attribute. */
    private static final String ISSUE_TITLE = "Title";
    /** issue.Description attribute. */
    private static final String ISSUE_DESCR = "Description";

    /** severity value: error. */
    private static final String SEVERITY_CRITICAL = "CRITICAL";
    /** severity value: high. */
    private static final String SEVERITY_HIGH = "HIGH";
    /** severity value: medium. */
    private static final String SEVERITY_MEDIUM = "MEDIUM";
    /** severity value: low. */
    private static final String SEVERITY_LOW = "LOW";
    /** severity value: unknown. */
    private static final String SEVERITY_UNKNOWN = "UNKNOWN";

    @Override
    public Report parse(final ReaderFactory readerFactory) throws ParsingException {
        try (Reader reader = readerFactory.create()) {
            Report report = new Report();
            Object object = new JSONTokener(reader).nextValue();

            if (object instanceof JSONArray) {
                JSONArray jsonReports = (JSONArray) object;
                for (Object reportObject: jsonReports) {
                    if (reportObject instanceof JSONObject) {
                        report.addAll(extractIssues((JSONObject) reportObject));
                    }
                }
            }

            return report;
        }
        catch (IOException e) {
            throw new ParsingException(e);
        }
    }

    private Report extractIssues(final JSONObject jsonReport) {
        Report report = new Report();
        JSONArray issues = parseIssuesFromReport(jsonReport);
        String fileName = parseFileNameFromReport(jsonReport);
        String category = parseCategoryFromReport(jsonReport);

        if (issues == null) {
            return report;
        }
        for (Object object: issues) {
            if (object instanceof JSONObject) {
                report.add(createIssueFromJsonObject((JSONObject) object, fileName, category));
            }
        }
        return report;
    }

    private Issue createIssueFromJsonObject(final JSONObject issue, final String fileName, final String category) {
        return new IssueBuilder()
                .setFileName(fileName)
                .setMessage(parseMessage(issue))
                .setDescription(parseDescription(issue))
                .setSeverity(parseSeverity(issue))
                .setPackageName(parsePackageName(issue))
                .setCategory(category)
                .setType(parseType(issue))
                .build();
    }

    /**
     * Parse function for issue array from report object
     *
     * @param report the object to parse.
     *
     * @return the issue array.
     */
    private JSONArray parseIssuesFromReport(final JSONObject report) {
        return report.optJSONArray(REPORT_ISSUES);
    }

    /**
     * Parse function for file name from report object
     *
     * @param report the object to parse.
     *
     * @return the file name.
     */
    private String parseFileNameFromReport(final JSONObject report) {
        return report.optString(REPORT_TARGET, "");
    }

    /**
     * Parse function for category from report object
     *
     * @param report the object to parse.
     *
     * @return the category.
     */
    private String parseCategoryFromReport(final JSONObject report) {
        return report.optString(REPORT_TYPE, "");
    }

    /**
     * Parse function for severity.
     *
     * @param issue the object to parse.
     *
     * @return the severity.
     */
    private Severity parseSeverity(final JSONObject issue) {
        String str = issue.optString(ISSUE_SEVERITY, null);
        Severity severity = Severity.WARNING_LOW;

        if (str != null) {
            if (SEVERITY_CRITICAL.equals(str)) {
                severity = Severity.ERROR;
            } else if (SEVERITY_HIGH.equals(str)) {
                severity = Severity.WARNING_HIGH;
            } else if (SEVERITY_MEDIUM.equals(str)) {
                severity = Severity.WARNING_NORMAL;
            } else if (SEVERITY_LOW.equals(str)) {
                severity = Severity.WARNING_LOW;
            } else if (SEVERITY_UNKNOWN.equals(str)) {
                severity = Severity.WARNING_LOW;
            }
        }
        return severity;
    }

    /**
     * Parse function for type
     *
     * @param issue the object to parse.
     *
     * @return the type.
     */
    private String parseType(final JSONObject issue) {
        return issue.optString(ISSUE_TYPE, "");
    }

    /**
     * Parse function for package name
     *
     * @param issue the object to parse.
     *
     * @return the package name.
     */
    private String parsePackageName(final JSONObject issue) {
        return issue.optString(ISSUE_PKGNAME, "");
    }

    /**
     * Parse function for message
     *
     * @param issue the object to parse.
     *
     * @return the message.
     */
    private String parseMessage(final JSONObject issue) {
        return issue.optString(ISSUE_TITLE, "");
    }

    /**
     * Parse function for description
     *
     * @param issue the object to parse.
     *
     * @return the description.
     */
    private String parseDescription(final JSONObject issue) {
        return issue.optString(ISSUE_DESCR, "");
    }
}
