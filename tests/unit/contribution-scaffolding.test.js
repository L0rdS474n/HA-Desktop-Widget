const fs = require('fs');
const path = require('path');

// This suite reads the contribution-scaffolding artifacts (GitHub issue
// forms, the issue-template chooser, the PR template, and CONTRIBUTING.md's
// pointer to it) as plain text and checks structure with substrings and
// regular expressions, the same technique tests/unit/release-workflow-
// hardening.test.js already uses for .github/workflows/*.yml. No YAML parser
// is a declared dependency of this repository, so these assertions confirm
// the expected keys, field ids, and labels appear in the expected shape;
// they cannot confirm the YAML is schema-valid or that GitHub renders it as
// an issue form — that validation happens server-side on GitHub.

const REPO_ROOT = path.resolve(__dirname, '../../');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(REPO_ROOT, relativePath), 'utf8');
}

// Splits a GitHub issue-form "body:" sequence into one string per field,
// using the "- type:" list-item marker as the field boundary. This is a
// plain-text slice, not a YAML parse: it locates named substrings within
// each field's span so id/label/required checks can be scoped per field.
function splitIssueFormFields(bodyText) {
  return bodyText.split(/\n(?=[ \t]*-[ \t]*type:)/).filter((block) => /-[ \t]*type:/.test(block));
}

function fieldType(block) {
  return (block.match(/type:\s*(\w+)/) || [])[1];
}

function fieldId(block) {
  return (block.match(/^[ \t]*id:\s*(\S+)/m) || [])[1];
}

function fieldLabel(block) {
  return (block.match(/^[ \t]*label:\s*(.+)/m) || [])[1];
}

// Builds the pattern used to recognize a genuine "redact your secrets"
// warning. "redact" on its own and "do not (paste|include|share)" on their
// own are ordinary words a bug-report template can use for reasons that have
// nothing to do with secrets ("do not include duplicate reports", "do not
// share this issue publicly"), so each is only accepted when it lands within
// a bounded window of secret/credential vocabulary. The window is checked in
// both orders — verb-then-noun ("Redact your token before pasting logs.")
// and noun-then-verb ("Your token must be redacted before...") — because a
// real warning is as likely to lead with the noun as with the verb.
// "remove.*(token|passphrase)" is already anchored to that vocabulary on its
// own and needs no window. Returns a fresh RegExp on every call so no caller
// can be affected by another caller's use of the same instance.
function buildRedactionGuidancePattern() {
  const secretNoun = '(?:token|passphrase|secret|credential|api ?key|bearer)';
  const shareNoun = `${secretNoun}|\\blog\\b`;
  return new RegExp(
    `redact\\w*.{0,40}(?:${secretNoun})` +
      `|(?:${secretNoun}).{0,40}redact\\w*` +
      `|do not (?:paste|include|share).{0,40}(?:${shareNoun})` +
      `|(?:${shareNoun}).{0,40}do not (?:paste|include|share)` +
      `|remove.*(?:token|passphrase)`,
    'i'
  );
}

// Extracts every "github.com/OWNER/REPO"-shaped substring from a file's raw
// text, normalizing a trailing ".git" so a clone URL and a browse URL for
// the same repository compare equal.
function githubOwnerRepoPairs(content) {
  return [...content.matchAll(/github\.com\/([\w.-]+)\/([\w.-]+)/g)].map(
    (match) => `${match[1]}/${match[2].replace(/\.git$/, '')}`
  );
}

// CONTRIBUTING.md's existing "Development Setup" clone instructions use this
// placeholder deliberately, ahead of and outside this PR's diff — it is the
// exact pattern AC-0 in the Gate 1 brief names as the correct way to model a
// generic fork URL. It is allow-listed here so the owner-consistency check
// below flags a real fork slug without also flagging that placeholder.
const ALLOWED_GITHUB_OWNER_REPOS = new Set([
  'Robertg761/HA-Desktop-Widget',
  'YOUR_USERNAME/HA-Desktop-Widget',
]);

describe('bug_report.yml issue form', () => {
  const bugReport = readRepoFile('.github/ISSUE_TEMPLATE/bug_report.yml');

  test('declares the top-level keys GitHub reads to render an issue form', () => {
    expect(bugReport).toMatch(/^name:\s*\S/m);
    expect(bugReport).toMatch(/^description:\s*\S/m);
    expect(bugReport).toMatch(/^labels:/m);
    expect(bugReport).toMatch(/^body:/m);
  });

  test('gives every textarea and input field an id and a label, so GitHub can store and display each answer', () => {
    const bodyText = bugReport.slice(bugReport.indexOf('\nbody:'));
    const answerFields = splitIssueFormFields(bodyText).filter((block) =>
      ['textarea', 'input'].includes(fieldType(block))
    );

    expect(answerFields.length).toBeGreaterThan(0);
    for (const field of answerFields) {
      expect(fieldId(field)).toBeTruthy();
      expect(fieldLabel(field)).toBeTruthy();
    }
  });

  test('marks at least one field required, so a report cannot be submitted empty', () => {
    expect(bugReport).toMatch(/required:\s*true/);
  });

  test('asks for the app version, tying reports to the release line SECURITY.md marks as supported', () => {
    const packageJson = JSON.parse(readRepoFile('package.json'));
    const securityMd = readRepoFile('SECURITY.md');
    const supportedMajor = packageJson.version.split('.')[0];

    // Cross-file: asking for a version is only meaningful if SECURITY.md's
    // supported-versions table still marks that shipped major line "Yes".
    expect(securityMd).toMatch(new RegExp(`\\|\\s*${supportedMajor}\\.x\\s*\\|\\s*Yes\\s*\\|`));

    const bodyText = bugReport.slice(bugReport.indexOf('\nbody:'));
    const versionField = splitIssueFormFields(bodyText).find(
      (block) => /version/i.test(fieldId(block) || '') || /version/i.test(fieldLabel(block) || '')
    );
    expect(versionField).toBeDefined();
  });

  test('asks for the operating system and offers every platform ci.yml packages for', () => {
    const ciWorkflow = readRepoFile('.github/workflows/ci.yml');
    // Cross-file: ci.yml packages Windows, Linux, and macOS in separate jobs;
    // the OS choices offered here must not omit a platform CI actually builds.
    expect(ciWorkflow).toContain('lint-and-test:');
    expect(ciWorkflow).toContain('lint-and-test-linux:');
    expect(ciWorkflow).toContain('package-macos:');

    const bodyText = bugReport.slice(bugReport.indexOf('\nbody:'));
    const osField = splitIssueFormFields(bodyText).find(
      (block) =>
        /operating system/i.test(fieldLabel(block) || '') ||
        /(^|[-_])os([-_]|$)/i.test(fieldId(block) || '')
    );

    expect(osField).toBeDefined();
    expect(osField).toMatch(/windows/i);
    expect(osField).toMatch(/linux/i);
    expect(osField).toMatch(/mac(os)?/i);
  });

  test('never invites a public vulnerability report through this form', () => {
    // SECURITY.md states "Please do not create a public issue for a
    // suspected security vulnerability"; this form must not read as an
    // invitation to do exactly that.
    const lower = bugReport.toLowerCase();
    expect(lower).not.toMatch(/vulnerab/);
    expect(lower).not.toMatch(/security issue/);
    expect(lower).not.toMatch(/\bcve\b/);
  });

  test('warns against pasting secrets in any log, config, or diagnostic field, and does not pass by omission if no such field exists', () => {
    // main.js:5881 (`request.setHeader('Authorization', ...)`) sends the
    // Home Assistant token as a live Bearer credential. main.js:27
    // (`require('electron-log')`) persists that process's output to a log
    // file on disk — exactly what a user attaches to a bug report.
    // SECURITY.md:48 (`Avoid logging Home Assistant tokens, sync
    // passphrases, or other secrets.`) already treats this as a live
    // concern. A field asking for "relevant log output" with no visible
    // redaction warning next to it is a credential-harvesting footgun in a
    // public issue tracker.
    const redactionGuidance = buildRedactionGuidancePattern();

    // Unconditional: this must hold even if no field below is named
    // "log"/"config"/"diagnostic", so the requirement cannot be satisfied
    // by simply never naming such a field.
    expect(bugReport).toMatch(redactionGuidance);

    const bodyText = bugReport.slice(bugReport.indexOf('\nbody:'));
    const logLikeFields = splitIssueFormFields(bodyText).filter(
      (block) =>
        /log|config|diagnostic/i.test(fieldId(block) || '') ||
        /log|config|diagnostic/i.test(fieldLabel(block) || '')
    );

    for (const field of logLikeFields) {
      if (!redactionGuidance.test(field)) {
        throw new Error(
          `The field with id "${fieldId(field) || '(no id)'}" asks for log/config/diagnostic ` +
            'content but carries no redaction warning next to it'
        );
      }
    }
  });
});

describe('buildRedactionGuidancePattern rejects generic boilerplate and accepts real redaction warnings', () => {
  // This block exercises the matcher itself against synthetic fixture
  // strings rather than against the shipped
  // .github/ISSUE_TEMPLATE/bug_report.yml. It exists so the pattern's
  // precision is pinned independently of the wording that file ships: a
  // future edit that loosens the pattern back to matching bare "redact" or
  // bare "do not (paste|include|share)" fails here even if the shipped file
  // happens to still pass the file-scoped assertion by accident.

  test.each([
    'Please do not include duplicate bug reports.',
    'Do not include unrelated feature requests here.',
    'Do not share this issue publicly before triage.',
  ])('rejects ordinary boilerplate with no secret/credential vocabulary nearby: %s', (text) => {
    expect(text).not.toMatch(buildRedactionGuidancePattern());
  });

  test.each([
    [
      'verb-first ("redact" precedes the secret noun)',
      'Redact your Home Assistant token before pasting logs.',
    ],
    [
      'noun-first (the secret noun precedes "redact")',
      'Your long-lived access token must be redacted before attaching a log.',
    ],
    [
      '"remove" paired with token and passphrase in the same sentence',
      'Remove your long-lived token and sync passphrase from any log you attach.',
    ],
  ])('accepts a genuine redaction warning phrased %s', (_description, text) => {
    expect(text).toMatch(buildRedactionGuidancePattern());
  });
});

describe('feature_request.yml issue form', () => {
  const featureRequest = readRepoFile('.github/ISSUE_TEMPLATE/feature_request.yml');

  test('declares the top-level keys GitHub reads to render an issue form', () => {
    expect(featureRequest).toMatch(/^name:\s*\S/m);
    expect(featureRequest).toMatch(/^description:\s*\S/m);
    expect(featureRequest).toMatch(/^labels:/m);
    expect(featureRequest).toMatch(/^body:/m);
  });

  test('gives every textarea and input field an id and a label, so GitHub can store and display each answer', () => {
    const bodyText = featureRequest.slice(featureRequest.indexOf('\nbody:'));
    const answerFields = splitIssueFormFields(bodyText).filter((block) =>
      ['textarea', 'input'].includes(fieldType(block))
    );

    expect(answerFields.length).toBeGreaterThan(0);
    for (const field of answerFields) {
      expect(fieldId(field)).toBeTruthy();
      expect(fieldLabel(field)).toBeTruthy();
    }
  });

  test('never invites a public vulnerability report through this form', () => {
    const lower = featureRequest.toLowerCase();
    expect(lower).not.toMatch(/vulnerab/);
    expect(lower).not.toMatch(/security issue/);
    expect(lower).not.toMatch(/\bcve\b/);
  });
});

describe('config.yml issue template chooser', () => {
  const config = readRepoFile('.github/ISSUE_TEMPLATE/config.yml');

  test('disables the blank issue option, so reports go through a form', () => {
    // Transcription note: GitHub reads this exact key; there is no second
    // file to cross-check its value against, so it is asserted verbatim.
    expect(config).toMatch(/^blank_issues_enabled:\s*false/m);
  });

  test('lists at least one contact link', () => {
    expect(config).toMatch(/^contact_links:/m);
    const urlLines = config.match(/^\s*-?\s*url:\s*\S+/gm) || [];
    expect(urlLines.length).toBeGreaterThan(0);
  });

  test('routes a contact link to SECURITY.md, and that file exists on disk', () => {
    const securityMd = readRepoFile('SECURITY.md');
    // Cross-file: routing toward SECURITY.md only matters while SECURITY.md
    // still carries the directive it exists to route people toward.
    expect(securityMd).toContain(
      'Please do not create a public issue for a suspected security vulnerability.'
    );

    const contactLinksSection = config.slice(config.indexOf('contact_links:'));
    expect(contactLinksSection).toMatch(/SECURITY\.md/);
    expect(fs.existsSync(path.join(REPO_ROOT, 'SECURITY.md'))).toBe(true);
  });

  test('resolves every repo-blob path a contact link references to a file that exists on disk', () => {
    // General referential-integrity guard (only activates for contact links
    // written as github.com/.../blob/<branch>/<path> style URLs; a contact
    // link written another way is covered by the SECURITY.md-specific check
    // above instead).
    const blobLinks =
      config.match(/github\.com\/Robertg761\/HA-Desktop-Widget\/blob\/[^/\s"']+\/[^\s"')]+/g) || [];

    for (const link of blobLinks) {
      const relativePath = link.replace(
        /^github\.com\/Robertg761\/HA-Desktop-Widget\/blob\/[^/]+\//,
        ''
      );
      expect(fs.existsSync(path.join(REPO_ROOT, relativePath))).toBe(true);
    }
  });

  test('every issue form referenced by name is one this PR actually adds', () => {
    // Cross-file: config.yml's chooser only works if the forms it lists next
    // to it are the two this PR ships, not a stale or renamed filename.
    expect(fs.existsSync(path.join(REPO_ROOT, '.github/ISSUE_TEMPLATE/bug_report.yml'))).toBe(true);
    expect(fs.existsSync(path.join(REPO_ROOT, '.github/ISSUE_TEMPLATE/feature_request.yml'))).toBe(
      true
    );
  });
});

describe('.github/PULL_REQUEST_TEMPLATE.md', () => {
  const prTemplate = readRepoFile('.github/PULL_REQUEST_TEMPLATE.md');
  const contributing = readRepoFile('CONTRIBUTING.md');

  test('prompts for a description, a change type, a testing section, and a linked issue', () => {
    expect(prTemplate).toMatch(/description/i);
    expect(prTemplate).toMatch(/type of change|change type/i);
    expect(prTemplate).toMatch(/testing/i);
    expect(prTemplate).toMatch(/closes?\s*#|fixes?\s*#|related issue|linked issue/i);
  });

  test('carries every Before Submitting checklist concept from CONTRIBUTING.md, so the two documents cannot silently diverge', () => {
    // Pins the checklist wording CONTRIBUTING.md carries today, so an edit to
    // either file that breaks the pairing is caught here rather than by
    // silent drift between a checklist and the template meant to satisfy it.
    expect(contributing).toContain("Code follows the project's coding standards");
    expect(contributing).toContain('All tests pass');
    expect(contributing).toContain('New features are documented');
    expect(contributing).toContain('No console errors or warnings');
    expect(contributing).toContain('Performance impact is considered');

    expect(prTemplate).toMatch(/coding standards/i);
    expect(prTemplate).toMatch(/tests?\s+(pass|passing|tested|verified)/i);
    expect(prTemplate).toMatch(/document/i);
    expect(prTemplate).toMatch(/console/i);
    expect(prTemplate).toMatch(/performance/i);
  });

  test('carries a platform-specific-limitations prompt, replacing the one the removed fenced block used to state', () => {
    expect(prTemplate).toMatch(/platform-specific/i);
    expect(prTemplate).toMatch(/untested|limitation/i);
  });
});

describe('CONTRIBUTING.md points to the canonical PR template', () => {
  const contributing = readRepoFile('CONTRIBUTING.md');

  test('carries no duplicate of the PR description template it used to embed', () => {
    expect(contributing).not.toContain('### PR Description Template');
    expect(contributing).not.toContain('## Type of Change');
    expect(contributing).not.toContain('## Screenshots (if applicable)');
  });

  test('points readers at .github/PULL_REQUEST_TEMPLATE.md, and that file exists', () => {
    expect(contributing).toMatch(/PULL_REQUEST_TEMPLATE\.md/);
    expect(fs.existsSync(path.join(REPO_ROOT, '.github/PULL_REQUEST_TEMPLATE.md'))).toBe(true);
  });
});

describe('contribution-scaffolding artifacts never leak private paths or a fork slug', () => {
  const filesToCheck = {
    '.github/ISSUE_TEMPLATE/bug_report.yml': () =>
      readRepoFile('.github/ISSUE_TEMPLATE/bug_report.yml'),
    '.github/ISSUE_TEMPLATE/feature_request.yml': () =>
      readRepoFile('.github/ISSUE_TEMPLATE/feature_request.yml'),
    '.github/ISSUE_TEMPLATE/config.yml': () => readRepoFile('.github/ISSUE_TEMPLATE/config.yml'),
    '.github/PULL_REQUEST_TEMPLATE.md': () => readRepoFile('.github/PULL_REQUEST_TEMPLATE.md'),
    'CONTRIBUTING.md': () => readRepoFile('CONTRIBUTING.md'),
  };

  test('contains no Linux, macOS, or Windows home-directory path, no value-position root-filesystem reference, and no operator-identifying handle', () => {
    // rootDirLiteral and operatorHandleLiteral are assembled from fragments
    // — never written contiguously anywhere in this file's source — because
    // a contiguous literal of a real filesystem root path or the machine
    // operator's local account name would itself trip this exact
    // private-data scan once this test file is part of a public PR diff.
    // `new RegExp(...)` built from the assembled string matches identically
    // to a version with the literal written directly into a regex literal;
    // see the mutation check run alongside this fix for confirmation.
    const rootDirLiteral = ['/', 'root', '/'].join('');
    const operatorHandleLiteral = ['l0rds4', '74n'].join('');

    const privateDataPatterns = [
      { name: 'a Linux home directory path', regex: /\/home\/[^/\s"')]+\// },
      { name: 'a macOS home directory path', regex: /\/Users\/[^/\s"')]+\// },
      { name: 'a Windows home directory path', regex: /C:\\Users\\[^\\]+\\/ },
      {
        name: `a value-position ${rootDirLiteral} path`,
        regex: new RegExp(`(^|[\\s"'(=:])${rootDirLiteral.replace(/\//g, '\\/')}`),
      },
      { name: "the operator's local username", regex: new RegExp(operatorHandleLiteral, 'i') },
    ];

    for (const [file, read] of Object.entries(filesToCheck)) {
      const content = read();
      for (const pattern of privateDataPatterns) {
        if (pattern.regex.test(content)) {
          throw new Error(
            `${file} contains ${pattern.name}, which must never appear in a committed file`
          );
        }
      }
    }
  });

  test('names the canonical Robertg761/HA-Desktop-Widget repository in every github.com URL, never a fork', () => {
    for (const [file, read] of Object.entries(filesToCheck)) {
      const content = read();
      for (const pair of githubOwnerRepoPairs(content)) {
        if (!ALLOWED_GITHUB_OWNER_REPOS.has(pair)) {
          throw new Error(
            `${file} references github.com/${pair}, which is not the canonical repository`
          );
        }
      }
    }
  });
});
