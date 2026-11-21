import { useState, type FormEvent } from 'react';
import { Button, ErrorBox, Field, inputCls } from '../components/ui';
import { useSession } from '../state';

export default function Login() {
  const { login } = useSession();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try { await login(email, password); } catch (err) { setError(err instanceof Error ? err.message : 'Login failed'); } finally { setBusy(false); }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-950 px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-2xl border border-slate-800 bg-slate-900/70 p-8">
        <div className="flex items-center gap-3">
          <img src="/favicon.svg" alt="" className="h-9 w-9" />
          <div>
            <h1 className="text-lg font-semibold text-white">VulnReplay</h1>
            <p className="text-xs text-slate-400">Reproduce yesterday's security incident. Prevent tomorrow's.</p>
          </div>
        </div>
        <Field label="Email"><input className={inputCls} type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} /></Field>
        <Field label="Password"><input className={inputCls} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} /></Field>
        <ErrorBox message={error} />
        <Button type="submit" disabled={busy} className="w-full justify-center">{busy ? 'Signing in…' : 'Sign in'}</Button>
      </form>
    </div>
  );
}
