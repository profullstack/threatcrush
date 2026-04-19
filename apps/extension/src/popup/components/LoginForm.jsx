import React, { useState } from 'react';
import { useAuthStore } from '../../store/auth';

const APP_URL = import.meta.env.VITE_APP_URL || 'https://threatcrush.com';

export default function LoginForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const { login, error, loading } = useAuthStore();

  async function handleSubmit(e) {
    e.preventDefault();
    await login(email, password);
  }

  return (
    <div className="flex flex-col items-center justify-center h-[520px] px-6">
      {/* Logo */}
      <div className="mb-6 text-center">
        <div className="text-4xl mb-2">⛨</div>
        <h1 className="text-xl font-bold text-white font-mono">ThreatCrush</h1>
        <p className="text-xs text-gray-500 mt-1">Sign in to your account</p>
      </div>

      {/* Login Form */}
      <form onSubmit={handleSubmit} className="w-full space-y-3">
        {error && (
          <div className="p-2 bg-red-500/10 border border-red-500/30 rounded-lg text-xs text-red-400">
            {error}
          </div>
        )}

        <div>
          <label className="block text-xs text-gray-500 mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            className="w-full px-3 py-2 bg-[#111] border border-[#222] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00ff41] transition-colors"
            placeholder="you@example.com"
          />
        </div>

        <div>
          <label className="block text-xs text-gray-500 mb-1">Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            className="w-full px-3 py-2 bg-[#111] border border-[#222] rounded-lg text-sm text-white placeholder-gray-600 focus:outline-none focus:border-[#00ff41] transition-colors"
            placeholder="••••••••"
          />
        </div>

        <button
          type="submit"
          disabled={loading}
          className="w-full py-2.5 bg-[#00ff41] text-black font-semibold text-sm rounded-lg hover:bg-[#00e03a] transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loading ? 'Signing in...' : 'Sign In'}
        </button>
      </form>

      {/* Sign up link */}
      <p className="mt-4 text-xs text-gray-500">
        Don't have an account?{' '}
        <a
          href={APP_URL}
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#00ff41] hover:underline"
        >
          Sign up at threatcrush.com
        </a>
      </p>
    </div>
  );
}
