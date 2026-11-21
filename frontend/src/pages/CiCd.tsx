import { useState } from 'react';
import { download } from '../api';
import { Button, Card, Code, ErrorBox, NeedProject, PageHeader } from '../components/ui';
import { useSession } from '../state';

const WORKFLOW = `name: security-regression
on: [pull_request]
permissions:
  contents: read
  security-events: write   # upload SARIF to code scanning
jobs:
  vulnreplay:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install ./backend
      - name: Start the application under test (staging/ephemeral env)
        run: ./scripts/start-app-for-tests.sh   # your own startup
      - name: Run saved security regression tests
        env:
          VULNREPLAY_ALLOWED_HOSTS: '["localhost"]'
          VULNREPLAY_SECRET_OWNER_USERNAME: \${{ secrets.VR_OWNER_USERNAME }}
          VULNREPLAY_SECRET_OWNER_PASSWORD: \${{ secrets.VR_OWNER_PASSWORD }}
          VULNREPLAY_SECRET_ATTACKER_USERNAME: \${{ secrets.VR_ATTACKER_USERNAME }}
          VULNREPLAY_SECRET_ATTACKER_PASSWORD: \${{ secrets.VR_ATTACKER_PASSWORD }}
        run: |
          vulnreplay run regression-library/suite.json \\
            --target-url http://localhost:8001 \\
            --baseline regression-library/baselines.json \\
            --fail-on regression_detected,vulnerability_reproduced \\
            --json vulnreplay.json --sarif vulnreplay.sarif
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: vulnreplay.sarif }`;

export default function CiCd() {
  const { project } = useSession();
  const [error, setError] = useState<string | null>(null);
  if (!project) return <NeedProject />;
  return (
    <>
      <PageHeader title="CI/CD Integrations" subtitle="Run the approved regression library on every pull request and fail the build on security regressions." />
      <div className="grid gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card title="GitHub Actions workflow"><Code className="max-h-[36rem]">{WORKFLOW}</Code></Card>
        </div>
        <div className="space-y-6">
          <Card title="1. Export the suite">
            <p className="mb-3 text-sm text-slate-400">Approved tests only, as a versioned JSON suite. Commit it to <code>regression-library/</code>.</p>
            <Button onClick={() => download(`/projects/${project.id}/tests-export`, 'suite.json').catch((e) => setError(e.message))}>Download suite.json</Button>
            <ErrorBox message={error} />
          </Card>
          <Card title="2. Configure secrets">
            <p className="text-sm text-slate-400">Tests reference credentials as <code>{'{{secret:NAME}}'}</code>. Provide them as <code>VULNREPLAY_SECRET_NAME</code> from GitHub encrypted secrets. Values are redacted from every log, JSON and SARIF output.</p>
          </Card>
          <Card title="3. Exit codes">
            <ul className="space-y-1 text-sm text-slate-300">
              <li><code>0</code> — no configured failure classes</li>
              <li><code>1</code> — at least one result in <code>--fail-on</code></li>
              <li><code>2</code> — target not in the allowlist / configuration error</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  );
}
