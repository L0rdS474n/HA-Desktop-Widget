const fs = require('fs');
const path = require('path');

// This suite reads .github/CODEOWNERS, .github/dependabot.yml, and
// .github/workflows/codeql.yml as plain text and checks structure with
// substrings and regular expressions, the same technique
// tests/unit/release-workflow-hardening.test.js and
// tests/unit/contribution-scaffolding.test.js already use for workflow and
// issue-form YAML. No YAML parser is a declared dependency of this
// repository, so these assertions confirm the expected keys, entries, and
// values appear in the expected shape; they cannot confirm the YAML is
// schema-valid, that GitHub requests review from the CODEOWNERS entry, or
// that a CodeQL run actually completes with the granted permissions. Those
// three are server-side. The schema-validity gap has a known route around
// it that stays outside this suite: after PR-1 merged, its three issue-form
// YAML files were validated against SchemaStore's official schemas using
// `ajv` and `js-yaml`, both already resolvable transitively from
// node_modules, with nothing added to package.json and nothing written into
// the repository. The same route is available for dependabot.yml and
// codeql.yml, both of which already exist in this repository; it is simply
// not run from inside Jest.

const REPO_ROOT = path.resolve(__dirname, '../../');

function readRepoFile(relativePath) {
  return fs.readFileSync(path.join(REPO_ROOT, relativePath), 'utf8');
}

// Extracts every "github.com/OWNER/REPO"-shaped substring from a file's raw
// text, normalizing a trailing ".git" so a clone URL and a browse URL for
// the same repository compare equal. Duplicated from
// tests/unit/contribution-scaffolding.test.js rather than imported: that
// file exports nothing, and each artifact-as-data suite in this repo reads
// its own target files independently.
function githubOwnerRepoPairs(content) {
  return [...content.matchAll(/github\.com\/([\w.-]+)\/([\w.-]+)/g)].map(
    (match) => `${match[1]}/${match[2].replace(/\.git$/, '')}`
  );
}

// Unlike CONTRIBUTING.md's existing clone-instructions placeholder (allow-
// listed in contribution-scaffolding.test.js), none of CODEOWNERS,
// dependabot.yml, or codeql.yml has a reason to carry a generic-fork
// placeholder URL, so only the canonical repository is ever acceptable here.
const ALLOWED_GITHUB_OWNER_REPOS = new Set(['Robertg761/HA-Desktop-Widget']);

// Returns every non-comment, non-blank line of a CODEOWNERS file. GitHub's
// own CODEOWNERS format has no continuation or multi-line construct, so a
// plain per-line split is a faithful read of the file, not an approximation
// of a real parser.
function codeownersRuleLines(content) {
  return content
    .split('\n')
    .filter((line) => line.trim().length > 0 && !line.trim().startsWith('#'));
}

// The first whitespace-delimited token on a CODEOWNERS rule line is the path
// pattern the rule applies to.
function ruleLinePathPattern(line) {
  return (line.match(/^(\S+)/) || [])[1];
}

function extractOwnerHandles(text) {
  return text.match(/@[\w-]+/g) || [];
}

// Splits dependabot.yml's "updates:" list into one string per entry, using
// the "- package-ecosystem:" list-item marker as the entry boundary — the
// same list-item-boundary-split technique
// tests/unit/contribution-scaffolding.test.js uses for issue-form fields,
// applied to a different list-item marker.
function splitDependabotUpdateEntries(dependabotYaml) {
  const updatesIndex = dependabotYaml.search(/(?:^|\n)updates:/);
  const updatesSection = updatesIndex === -1 ? '' : dependabotYaml.slice(updatesIndex);
  return updatesSection
    .split(/\n(?=[ \t]*-[ \t]*package-ecosystem:)/)
    .filter((block) => /package-ecosystem:/.test(block));
}

// Reads a single-line "key: value" field out of a YAML block and strips one
// layer of surrounding quotes, so both `directory: "/"` and `directory: /`
// compare equal to the plain string "/". The optional "(?:-[ \t]*)?" admits
// the case splitDependabotUpdateEntries always produces for the first field
// of an entry -- "  - package-ecosystem: 'npm'" -- where the YAML list-item
// dash sits between the leading indentation and the key itself; every other
// field in an entry (directory, schedule, interval, day) has no dash there,
// and the group is optional so those still match exactly as before.
//
// What this regex actually guarantees is the first match in document order
// within the block it is given -- not a structural nesting boundary. It has
// no notion of indentation depth, so if the same key name appeared again,
// nested one level deeper than the field this call actually wants, but
// earlier in the block's text, that deeper-nested line would win and this
// function would silently return the wrong value instead of erroring. That
// is safe today only because of two measured facts, not because the regex
// itself enforces it: every call site in this file passes fieldValue only
// "package-ecosystem" or "directory" as key, and .github/dependabot.yml
// contains zero "ignore:" blocks (the one dependabot key whose children --
// "dependency-name", "update-types", and so on -- would be the realistic
// source of a same-named key nested deeper than the intended one) and reuses
// neither "package-ecosystem" nor "directory" at any second nesting level
// anywhere in the file. Re-check both facts before this suite starts calling
// fieldValue with a different key, or before dependabot.yml gains an
// "ignore:" block or any other nested mapping.
function fieldValue(block, key) {
  const match = block.match(new RegExp(`(?:^|\\n)[ \\t]*(?:-[ \\t]*)?${key}:[ \\t]*(.+)`));
  if (!match) return undefined;
  return match[1].trim().replace(/^["']|["']$/g, '');
}

// Groups consecutive "#"-prefixed lines into single multi-line comment
// blocks, so a two- or three-line explanation can be matched as one span
// instead of requiring the whole trigger condition to fit on a single line.
function extractCommentBlocks(yamlText) {
  const blocks = [];
  let current = null;
  for (const line of yamlText.split('\n')) {
    if (/^\s*#/.test(line)) {
      current = current === null ? line : `${current}\n${line}`;
    } else if (current !== null) {
      blocks.push(current);
      current = null;
    }
  }
  if (current !== null) blocks.push(current);
  return blocks;
}

// Extracts a top-level YAML key's block: the "key:" line itself plus every
// contiguous line after it that starts with leading whitespace. A blank
// line or the next column-0 key ends the block, which is exactly how the
// section boundary works in the workflow files this repository already
// ships.
function topLevelSection(yamlText, key) {
  const match = yamlText.match(new RegExp(`\\n${key}:[^\\n]*\\n(?:[ \\t]+[^\\n]*\\n?)*`));
  return match ? match[0] : undefined;
}

// Returns everything in a workflow file from its top-level "jobs:" key
// through the end of the file. Deliberately not built on topLevelSection:
// that helper's match stops dead at the first blank line, and a real jobs:
// block is full of blank lines between steps (ci.yml's own jobs: section
// has one after nearly every field), so topLevelSection("jobs") would
// silently return only the first few lines of a job -- hiding whatever
// comes after that first blank line, including a job-level permissions:
// key. "jobs:" is always the last top-level key GitHub Actions recognizes
// in a workflow file, so reading to the literal end of the file excludes
// nothing that could legitimately follow it.
function jobsSectionToEndOfFile(yamlText) {
  const match = yamlText.match(/\njobs:[^\n]*\n[\s\S]*$/);
  return match ? match[0] : undefined;
}

// Parses a YAML mapping block's direct "key: value" child lines -- every
// line indented under the block's own header line, holding a single scalar
// token right after the colon, with an optional trailing "# comment"
// tolerated. The header line itself (e.g. the "permissions:" line
// topLevelSection returns as part of its match) has no leading indentation,
// so it is deliberately excluded by the required "^[ \t]+" prefix: this
// walks only the block's children, never the key that introduces it, and it
// does not descend into a nested mapping value (this workflow's permissions
// block never has one). Strips one layer of surrounding quotes from the
// captured value -- the same normalization fieldValue already applies to
// dependabot.yml fields -- so `security-events: "write"` and
// `security-events: write` parse to the identical map entry for the purposes
// of *this* helper's callers (the "grants exactly" key-set test below). That
// is narrower than "this suite requires unquoted scalars": the sibling
// presence test just above, which does not go through this helper, is
// deliberately stricter and rejects a quoted value -- see the comment on
// that test for why the two checks are allowed to disagree.
function flatMappingEntries(block) {
  return [...block.matchAll(/^[ \t]+([\w-]+):[ \t]*(\S+)(?:[ \t]+#.*)?[ \t]*$/gm)].map((match) => [
    match[1],
    match[2].replace(/^["']|["']$/g, ''),
  ]);
}

describe('.github/CODEOWNERS', () => {
  // CODEOWNERS assigns reviewers only when the named account already holds
  // write access on the repository hosting the file. That account holds
  // write access on the upstream repository this PR targets, not on the
  // fork this branch lives on, so GitHub cannot exercise this file's actual
  // effect from here. This block checks the parts a plain-text read can
  // check: rule-line syntax, catch-all path coverage, and owner identity —
  // including that the identity matches SECURITY.md, so the two cannot
  // silently name two different maintainers.
  const codeowners = readRepoFile('.github/CODEOWNERS');
  const ruleLines = codeownersRuleLines(codeowners);

  test('gives every non-comment, non-blank line a path pattern followed by one or more @handle owners', () => {
    expect(ruleLines.length).toBeGreaterThan(0);
    for (const line of ruleLines) {
      expect(line).toMatch(/^\S+\s+(@[\w-]+\s*)+$/);
    }
  });

  test('contains a catch-all "*" rule assigning @Robertg761', () => {
    const catchAllLine = ruleLines.find((line) => ruleLinePathPattern(line) === '*');
    expect(catchAllLine).toBeDefined();
    expect(extractOwnerHandles(catchAllLine)).toEqual(['@Robertg761']);
  });

  test('names no handle other than @Robertg761 on any rule line', () => {
    const allHandles = ruleLines.flatMap(extractOwnerHandles);
    expect(allHandles.length).toBeGreaterThan(0);
    for (const handle of allHandles) {
      expect(handle).toBe('@Robertg761');
    }
  });

  test("names the same maintainer handle SECURITY.md's Contact Information section names, so the two cannot drift apart silently", () => {
    const securityMd = readRepoFile('SECURITY.md');
    const contactSection = securityMd.slice(securityMd.indexOf('## Contact Information'));
    const contactHandleMatch = contactSection.match(
      /\*\*GitHub\*\*:\s*\[(@[\w-]+)\]\(https:\/\/github\.com\/[\w-]+\)/
    );
    expect(contactHandleMatch).not.toBeNull();
    const contactHandle = contactHandleMatch[1];

    const codeownersHandles = new Set(ruleLines.flatMap(extractOwnerHandles));
    expect(codeownersHandles.size).toBe(1);
    expect([...codeownersHandles][0]).toBe(contactHandle);
  });
});

describe('.github/dependabot.yml', () => {
  const dependabot = readRepoFile('.github/dependabot.yml');
  const entries = splitDependabotUpdateEntries(dependabot);

  test('declares version 2 and a top-level updates list', () => {
    expect(dependabot).toMatch(/^version:\s*2\s*$/m);
    expect(dependabot).toMatch(/^updates:/m);
  });

  test('lists exactly one npm ecosystem entry, rooted at "/" rather than a workspace package path', () => {
    const npmEntries = entries.filter((block) => fieldValue(block, 'package-ecosystem') === 'npm');
    expect(npmEntries).toHaveLength(1);
    expect(fieldValue(npmEntries[0], 'directory')).toBe('/');
  });

  test("the npm entry's directory resolves to a real package.json, so dependabot has an actual manifest to read", () => {
    const npmEntries = entries.filter((block) => fieldValue(block, 'package-ecosystem') === 'npm');
    const directory = fieldValue(npmEntries[0], 'directory');
    expect(fs.existsSync(path.join(REPO_ROOT, directory, 'package.json'))).toBe(true);
  });

  test('references no /packages/ path anywhere, matching npm workspaces hoisting into one root lockfile', () => {
    expect(dependabot).not.toMatch(/\/packages\//);
  });

  test('the workspace package that a /packages/ entry would target declares zero dependencies and zero devDependencies today', () => {
    // Cross-file: the "zero /packages/ entries" choice above is only correct
    // while this holds. If a future PR gives packages/widget-renderer a real
    // dependency, this assertion fails and the dependabot config choice
    // needs re-examining, rather than silently going stale.
    const widgetRenderer = JSON.parse(readRepoFile('packages/widget-renderer/package.json'));
    expect(widgetRenderer.dependencies || {}).toEqual({});
    expect(widgetRenderer.devDependencies || {}).toEqual({});
  });

  test('lists exactly one github-actions ecosystem entry, rooted at "/"', () => {
    const actionsEntries = entries.filter(
      (block) => fieldValue(block, 'package-ecosystem') === 'github-actions'
    );
    expect(actionsEntries).toHaveLength(1);
    expect(fieldValue(actionsEntries[0], 'directory')).toBe('/');
  });

  test('gives every update entry a schedule.interval', () => {
    expect(entries.length).toBeGreaterThan(0);
    for (const entry of entries) {
      expect(entry).toMatch(/schedule:\s*\n\s*interval:\s*\S+/);
    }
  });

  test('carries a comment naming the condition that would make a /packages/* entry necessary, not an open-ended TODO', () => {
    const commentBlocks = extractCommentBlocks(dependabot);
    const namesPackagesPath = /packages/i;
    const namesDependencyGain = /dependenc(?:y|ies)|devDependencies/i;
    const explainsTrigger = commentBlocks.some(
      (block) => namesPackagesPath.test(block) && namesDependencyGain.test(block)
    );
    expect(explainsTrigger).toBe(true);
  });
});

describe('.github/workflows/codeql.yml', () => {
  const codeql = readRepoFile('.github/workflows/codeql.yml');
  const ci = readRepoFile('.github/workflows/ci.yml');

  test('triggers on pull requests targeting main and on a weekly schedule', () => {
    const onSection = topLevelSection(codeql, 'on');
    expect(onSection).toBeDefined();
    expect(onSection).toMatch(/pull_request:\s*\n\s*branches:\s*\[\s*['"]?main['"]?\s*\]/);

    const cronMatch = onSection.match(/schedule:\s*\n\s*-\s*cron:\s*['"]([^'"]+)['"]/);
    expect(cronMatch).not.toBeNull();

    const cronFields = cronMatch[1].trim().split(/\s+/);
    expect(cronFields).toHaveLength(5);
    const [minute, hour, dayOfMonth, month, dayOfWeek] = cronFields;
    // A schedule that fires once a week needs one specific weekday and no
    // day-of-month/month restriction. Loosening any of these four checks
    // would let an every-minute or a nightly cron pass as "weekly".
    expect(minute).not.toBe('*');
    expect(hour).not.toBe('*');
    expect(dayOfMonth).toBe('*');
    expect(month).toBe('*');
    expect(dayOfWeek).toMatch(/^[0-6]$/);
  });

  test('never triggers on pull_request_target anywhere in the file', () => {
    // pull_request (not pull_request_target) is the deliberate choice for a
    // fork-origin run here: GitHub's own docs say a pull_request run from a
    // fork is capped to a read-only GITHUB_TOKEN with no access to other
    // secrets, that this workflow's own permissions: block cannot override
    // that cap, and that code scanning's SARIF upload is allowed under it
    // as a documented special case -- so pull_request already gets this
    // workflow everything it needs. pull_request_target would undo exactly
    // that protection by restoring the full permissions block and real
    // secrets to a fork-PR run. Checked against the whole file, not just
    // the "on:" section extracted above, because a pull_request_target key
    // has no legitimate reason to appear anywhere in this workflow -- not
    // only as a second trigger key alongside pull_request.
    expect(codeql).not.toMatch(/pull_request_target/);
  });

  test('declares its own permissions block granting security-events: write and contents: read', () => {
    // Gate 1 measured 0 occurrences of "security-events" across .github/**
    // at the base commit (grep over .github/, no match), so this workflow's
    // permissions cannot be inherited from any existing workflow file — it
    // has to state both keys itself.
    //
    // Deliberately strict, unlike flatMappingEntries below: these two regexes
    // require the unquoted scalar form (`security-events: write`, not
    // `security-events: "write"`) and will not match a quoted value. That is
    // an intentionally different rigor level from the "grants exactly"
    // test's flatMappingEntries helper, which does strip quotes -- this file
    // requires unquoted scalars for the permissions block's values, and the
    // stricter check here is what enforces that requirement rather than
    // silently accepting either style.
    const permissionsSection = topLevelSection(codeql, 'permissions');
    expect(permissionsSection).toBeDefined();
    expect(permissionsSection).toMatch(/^\s*security-events:\s*write\s*$/m);
    expect(permissionsSection).toMatch(/^\s*contents:\s*read\s*$/m);
  });

  test('grants exactly security-events: write and contents: read in its top-level permissions block, and nothing more', () => {
    // The test above confirms both required keys are present; this one
    // confirms they are the *only* keys, which is the actual least-
    // privilege property under test -- presence alone would still pass if a
    // future edit added, say, contents: write, actions: write, or
    // pull-requests: write alongside the required two. topLevelSection only
    // matches a "permissions:" key sitting at column 0, so this is asserted
    // against the workflow-level permissions block specifically, never a
    // per-job permissions block nested under jobs.*.permissions (those are
    // indented and topLevelSection's "\npermissions:" match cannot reach
    // them).
    const permissionsSection = topLevelSection(codeql, 'permissions');
    expect(permissionsSection).toBeDefined();

    const entries = flatMappingEntries(permissionsSection);
    // Fails loudly, not vacuously, if the block holds no parseable
    // "key: value" children -- e.g. if a future edit collapses it to the
    // single-line "permissions: write-all" form, which this parser
    // deliberately does not treat as an implicit key/value pair.
    expect(entries.length).toBeGreaterThan(0);

    const permissionsMap = Object.fromEntries(entries);
    expect(permissionsMap).toEqual({ 'security-events': 'write', contents: 'read' });
  });

  test('declares no job-level permissions: key anywhere under jobs:, so the workflow-level block above is the only source of the token any job receives', () => {
    // GitHub Actions lets a job declare its own permissions: key, and where
    // present it overrides the workflow-level block for that job rather
    // than merging with it -- so the exclusivity test above, which only
    // reads the workflow-level block, would describe a declaration that is
    // not the token the job actually runs with if a job-level override
    // existed alongside it. This workflow defines exactly one job and
    // GitHub's own reference CodeQL template carries no job-level
    // permissions: block, so there is no legitimate reason for one here.
    const jobsSection = jobsSectionToEndOfFile(codeql);
    // Fails loudly, not vacuously, if the "jobs:" key cannot even be found
    // -- the same discipline the permissions entries.length guard above
    // uses.
    expect(jobsSection).toBeDefined();
    // A second loud-failure guard: confirms the extracted region actually
    // reached real job content (every job declares runs-on:) rather than
    // stopping short of it, so the negative assertion below is checked
    // against the whole jobs: section instead of a truncated prefix that
    // would let it pass by accident.
    expect(jobsSection).toMatch(/runs-on:/);

    expect(jobsSection).not.toMatch(/^[ \t]+permissions:/m);
  });

  test('configures the analysis matrix for JavaScript/TypeScript', () => {
    expect(codeql).toMatch(/language:[^\n]*javascript/i);
  });

  test('pins every github/codeql-action/* step to @v4', () => {
    expect(codeql).toMatch(/github\/codeql-action\/init@v4/);
    expect(codeql).toMatch(/github\/codeql-action\/analyze@v4/);
  });

  test('contains zero references to any github/codeql-action/* step pinned to @v3', () => {
    // @v4 is the version this workflow's init/analyze steps are pinned to
    // above; this is a blanket sweep (not just init/analyze) so an autobuild
    // or upload-sarif step pinned to the older @v3 line would also fail this
    // check, keeping every codeql-action step on the one line the two pins
    // above already commit to.
    const v3References = codeql.match(/codeql-action\/[\w-]+@v3/g) || [];
    expect(v3References).toHaveLength(0);
  });

  test('uses the same actions/checkout major version ci.yml uses, so the two workflows cannot drift apart silently', () => {
    const ciCheckoutVersions = [...ci.matchAll(/actions\/checkout@(v\d+)/g)].map((m) => m[1]);
    expect(ciCheckoutVersions.length).toBeGreaterThan(0);

    const uniqueCiVersions = new Set(ciCheckoutVersions);
    // This invariant is only meaningful while ci.yml pins one consistent
    // version across its own jobs.
    expect(uniqueCiVersions.size).toBe(1);
    const [ciCheckoutVersion] = uniqueCiVersions;

    expect(codeql).toContain(`actions/checkout@${ciCheckoutVersion}`);
  });
});

describe('repo-automation artifacts never leak private paths, a fork slug, or the operator handle', () => {
  const filesToCheck = {
    '.github/CODEOWNERS': () => readRepoFile('.github/CODEOWNERS'),
    '.github/dependabot.yml': () => readRepoFile('.github/dependabot.yml'),
    '.github/workflows/codeql.yml': () => readRepoFile('.github/workflows/codeql.yml'),
  };

  test('contains no Linux, macOS, or Windows home-directory path, no value-position root-filesystem reference, and no operator-identifying handle', () => {
    // rootDirLiteral and operatorHandleLiteral are assembled from fragments
    // — never written contiguously anywhere in this file's source — for the
    // same reason tests/unit/contribution-scaffolding.test.js assembles
    // them: a contiguous literal of a real filesystem root path or the
    // machine operator's local account name would itself trip this exact
    // private-data scan once this test file is part of a public PR diff.
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
