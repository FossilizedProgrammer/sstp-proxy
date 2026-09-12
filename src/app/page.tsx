"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { VpnGateServer } from "./api/vpngate/route";

type Tab = "builder" | "vpngate" | "saved" | "downloads" | "about";

type Builder = {
  name: string;
  host: string;
  port: string;
  username: string;
  password: string;
  hub: string;
  auth: string;
  socksAddr: string;
  httpAddr: string;
  dns: string;
  mtu: string;
  proxy: string;
  connectAddr: string;
  sni: string;
  hostHeader: string;
  fingerprint: string;
  insecure: boolean;
  retry: boolean;
  verbose: boolean;
};

type SavedServer = {
  id: number;
  name: string;
  host: string;
  port: number;
  username: string;
  password: string;
  country: string;
  auth: string;
  socksAddr: string;
  httpAddr: string;
  notes: string;
};

const emptyBuilder: Builder = {
  name: "",
  host: "",
  port: "443",
  username: "vpn",
  password: "vpn",
  hub: "",
  auth: "auto",
  socksAddr: "127.0.0.1:1080",
  httpAddr: "127.0.0.1:8080",
  dns: "",
  mtu: "1400",
  proxy: "",
  connectAddr: "",
  sni: "",
  hostHeader: "",
  fingerprint: "",
  insecure: true,
  retry: true,
  verbose: false,
};

function buildCommand(b: Builder, exe = "sstp-proxy"): string {
  const parts = [exe, `-server ${b.host || "HOST"}`];
  if (b.port && b.port !== "443") parts.push(`-port ${b.port}`);
  parts.push(`-user ${b.username || "vpn"}`);
  parts.push(`-pass ${b.password || "vpn"}`);
  if (b.hub.trim()) parts.push(`-hub ${b.hub.trim()}`);
  if (b.auth && b.auth !== "auto") parts.push(`-auth ${b.auth}`);
  if (b.socksAddr) parts.push(`-socks ${b.socksAddr}`);
  else parts.push(`-socks ""`);
  if (b.httpAddr) parts.push(`-http ${b.httpAddr}`);
  else parts.push(`-http ""`);
  if (b.dns.trim()) parts.push(`-dns ${b.dns.trim()}`);
  if (b.proxy.trim()) parts.push(`-proxy ${b.proxy.trim()}`);
  if (b.connectAddr.trim()) parts.push(`-connect ${b.connectAddr.trim()}`);
  if (b.sni.trim()) parts.push(`-sni ${b.sni.trim()}`);
  if (b.hostHeader.trim()) parts.push(`-host-header ${b.hostHeader.trim()}`);
  if (b.fingerprint.trim()) parts.push(`-fingerprint ${b.fingerprint.trim()}`);
  if (b.mtu && b.mtu !== "1400") parts.push(`-mtu ${b.mtu}`);
  if (!b.insecure) parts.push(`-insecure=false`);
  if (b.retry) parts.push(`-retry`);
  if (b.verbose) parts.push(`-verbose`);
  return parts.join(" ");
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5 shadow-lg">
      <h3 className="mb-4 text-sm font-semibold uppercase tracking-wider text-sky-400">
        {title}
      </h3>
      {children}
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1 text-sm">
      <span className="text-slate-400">{label}</span>
      {children}
    </label>
  );
}

const inputCls =
  "rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100 outline-none focus:border-sky-500";

export default function Page() {
  const [tab, setTab] = useState<Tab>("builder");
  const [b, setB] = useState<Builder>(emptyBuilder);
  const [copied, setCopied] = useState(false);

  const set = <K extends keyof Builder>(k: K, v: Builder[K]) =>
    setB((prev) => ({ ...prev, [k]: v }));

  const cmd = useMemo(() => buildCommand(b), [b]);

  const copy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* ignore */
    }
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-8">
      <header className="mb-8">
        <div className="inline-flex items-center gap-2 rounded-full border border-sky-800 bg-sky-950/40 px-3 py-1 text-xs text-sky-300">
          <span className="h-2 w-2 rounded-full bg-emerald-400" />
          userspace SSTP · no system-wide VPN · no root
        </div>
        <h1 className="mt-4 bg-gradient-to-r from-sky-300 to-emerald-300 bg-clip-text text-4xl font-bold text-transparent">
          sstp-proxy control panel
        </h1>
        <p className="mt-2 max-w-3xl text-slate-400">
          A standalone command-line client for <b>MS-SSTP</b>,{" "}
          <b>SoftEther VPN Server</b> and public <b>VPN Gate</b> relays. It
          negotiates the SSTP tunnel entirely in userspace and exposes local{" "}
          <b>SOCKS5</b> and <b>HTTP</b> proxies, so you can route just your
          browser through the VPN without touching your OS routing table. This
          panel builds the exact command line, browses VPN Gate, and keeps your
          favorite servers.
        </p>
      </header>

      <nav className="mb-6 flex flex-wrap gap-2">
        {(
          [
            ["builder", "Command builder"],
            ["vpngate", "VPN Gate directory"],
            ["saved", "Saved servers"],
            ["downloads", "Build & download"],
            ["about", "How it works"],
          ] as [Tab, string][]
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`rounded-lg px-4 py-2 text-sm font-medium transition ${
              tab === id
                ? "bg-sky-500 text-white"
                : "bg-slate-800/60 text-slate-300 hover:bg-slate-800"
            }`}
          >
            {label}
          </button>
        ))}
      </nav>

      {tab === "builder" && (
        <BuilderTab
          b={b}
          set={set}
          cmd={cmd}
          copied={copied}
          copy={copy}
        />
      )}
      {tab === "vpngate" && (
        <VpnGateTab
          onUse={(s) => {
            setB({
              ...emptyBuilder,
              name: `${s.country} (${s.ddns || s.ip})`,
              host: s.ddns || s.ip,
              port: String(s.tcpPort || 443),
            });
            setTab("builder");
          }}
        />
      )}
      {tab === "saved" && (
        <SavedTab
          onUse={(s) => {
            setB({
              name: s.name,
              host: s.host,
              port: String(s.port),
              username: s.username,
              password: s.password,
              hub: "",
              auth: s.auth,
              socksAddr: s.socksAddr,
              httpAddr: s.httpAddr,
              dns: "",
              mtu: "1400",
              proxy: "",
              connectAddr: "",
              sni: "",
              hostHeader: "",
              fingerprint: "",
              insecure: true,
              retry: true,
              verbose: false,
            });
            setTab("builder");
          }}
        />
      )}
      {tab === "downloads" && <DownloadsTab />}
      {tab === "about" && <AboutTab />}

      <footer className="mt-12 border-t border-slate-800 pt-6 text-xs text-slate-500">
        The client source lives in <code className="text-slate-400">client/</code>.
        Crypto binding (HMAC-SHA1/256, PRF+/CMK/CMAC) and MS-CHAPv2 are unit
        tested against the official [MS-SSTP] and RFC 2759 vectors.
      </footer>
    </main>
  );
}

function BuilderTab({
  b,
  set,
  cmd,
  copied,
  copy,
}: {
  b: Builder;
  set: <K extends keyof Builder>(k: K, v: Builder[K]) => void;
  cmd: string;
  copied: boolean;
  copy: (t: string) => void;
}) {
  const [saveMsg, setSaveMsg] = useState("");

  const save = async () => {
    setSaveMsg("");
    if (!b.host.trim()) {
      setSaveMsg("Enter a host first.");
      return;
    }
    const res = await fetch("/api/servers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...b, port: Number(b.port) || 443 }),
    });
    const data = await res.json();
    setSaveMsg(data.ok ? "Saved!" : `Error: ${data.error}`);
  };

  return (
    <div className="grid gap-6 lg:grid-cols-[1.1fr_0.9fr]">
      <Section title="Connection">
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field label="Name (optional)">
            <input
              className={inputCls}
              value={b.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder="My VPN Gate server"
            />
          </Field>
          <Field label="Server host / IP">
            <input
              className={inputCls}
              value={b.host}
              onChange={(e) => set("host", e.target.value)}
              placeholder="219.100.37.12"
            />
          </Field>
          <Field label="Port">
            <input
              className={inputCls}
              value={b.port}
              onChange={(e) => set("port", e.target.value)}
            />
          </Field>
          <Field label="Auth method">
            <select
              className={inputCls}
              value={b.auth}
              onChange={(e) => set("auth", e.target.value)}
            >
              <option value="auto">auto</option>
              <option value="mschapv2">mschapv2</option>
              <option value="pap">pap</option>
            </select>
          </Field>
          <Field label="Username">
            <input
              className={inputCls}
              value={b.username}
              onChange={(e) => set("username", e.target.value)}
            />
          </Field>
          <Field label="Password">
            <input
              className={inputCls}
              value={b.password}
              onChange={(e) => set("password", e.target.value)}
            />
          </Field>
          <Field label="Virtual hub (SoftEther)">
            <input
              className={inputCls}
              value={b.hub}
              onChange={(e) => set("hub", e.target.value)}
              placeholder="e.g. vpngate (optional)"
            />
          </Field>
          <Field label="SOCKS5 listen">
            <input
              className={inputCls}
              value={b.socksAddr}
              onChange={(e) => set("socksAddr", e.target.value)}
            />
          </Field>
          <Field label="HTTP proxy listen">
            <input
              className={inputCls}
              value={b.httpAddr}
              onChange={(e) => set("httpAddr", e.target.value)}
            />
          </Field>
          <Field label="Extra DNS (comma sep)">
            <input
              className={inputCls}
              value={b.dns}
              onChange={(e) => set("dns", e.target.value)}
              placeholder="8.8.8.8,1.1.1.1"
            />
          </Field>
          <Field label="MTU">
            <input
              className={inputCls}
              value={b.mtu}
              onChange={(e) => set("mtu", e.target.value)}
            />
          </Field>
          <Field label="Upstream proxy (for censorship)">
            <input
              className={inputCls}
              value={b.proxy}
              onChange={(e) => set("proxy", e.target.value)}
              placeholder="socks5://127.0.0.1:9050 or http://host:port"
            />
          </Field>
          <Field label="TLS fingerprint (anti-DPI)">
            <select
              className={inputCls}
              value={b.fingerprint}
              onChange={(e) => set("fingerprint", e.target.value)}
            >
              <option value="">standard (Go)</option>
              <option value="chrome">chrome</option>
              <option value="firefox">firefox</option>
              <option value="safari">safari</option>
              <option value="edge">edge</option>
              <option value="ios">ios</option>
              <option value="android">android</option>
              <option value="random">random</option>
            </select>
          </Field>
          <Field label="SNI override ( - = none )">
            <input
              className={inputCls}
              value={b.sni}
              onChange={(e) => set("sni", e.target.value)}
              placeholder="- , or www.microsoft.com"
            />
          </Field>
          <Field label="Connect address (domain fronting)">
            <input
              className={inputCls}
              value={b.connectAddr}
              onChange={(e) => set("connectAddr", e.target.value)}
              placeholder="e.g. 106.158.139.230:1749"
            />
          </Field>
          <Field label="Host header override">
            <input
              className={inputCls}
              value={b.hostHeader}
              onChange={(e) => set("hostHeader", e.target.value)}
              placeholder="e.g. cdn.bigprovider.com"
            />
          </Field>
        </div>
        <div className="mt-4 flex flex-wrap gap-6">
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={b.insecure}
              onChange={(e) => set("insecure", e.target.checked)}
            />
            Skip TLS verify (VPN Gate / self-signed)
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={b.retry}
              onChange={(e) => set("retry", e.target.checked)}
            />
            Auto-reconnect on drop
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input
              type="checkbox"
              checked={b.verbose}
              onChange={(e) => set("verbose", e.target.checked)}
            />
            Verbose logging
          </label>
        </div>
        <div className="mt-5 flex items-center gap-3">
          <button
            onClick={save}
            className="rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400"
          >
            Save server
          </button>
          {saveMsg && (
            <span className="text-sm text-slate-400">{saveMsg}</span>
          )}
        </div>
      </Section>

      <div className="flex flex-col gap-6">
        <Section title="Generated command">
          <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-sm text-emerald-300">
            {cmd}
          </pre>
          <button
            onClick={() => copy(cmd)}
            className="mt-3 rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-400"
          >
            {copied ? "Copied!" : "Copy command"}
          </button>
        </Section>
        <Section title="Then, in your browser">
          <ol className="list-decimal space-y-2 pl-5 text-sm text-slate-300">
            <li>Run the command above in a terminal.</li>
            <li>
              Wait for <code className="text-emerald-300">tunnel is UP</code>.
            </li>
            <li>
              Set your browser SOCKS5 proxy to{" "}
              <code className="text-emerald-300">{b.socksAddr || "127.0.0.1:1080"}</code>{" "}
              (or HTTP proxy to{" "}
              <code className="text-emerald-300">{b.httpAddr || "127.0.0.1:8080"}</code>).
            </li>
            <li>
              For SOCKS5 in Firefox, enable{" "}
              <em>&ldquo;Proxy DNS when using SOCKS v5&rdquo;</em> so DNS is
              resolved through the tunnel too.
            </li>
          </ol>
        </Section>
      </div>
    </div>
  );
}

function VpnGateTab({ onUse }: { onUse: (s: VpnGateServer) => void }) {
  const [servers, setServers] = useState<VpnGateServer[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [q, setQ] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const res = await fetch("/api/vpngate");
      const data = await res.json();
      setServers(data.servers ?? []);
      if (!data.ok) setError(data.error ?? "Failed to load");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const save = async (s: VpnGateServer) => {
    await fetch("/api/servers", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        name: `${s.country} (${s.ddns || s.ip})`,
        host: s.ddns || s.ip,
        port: s.tcpPort || 443,
        country: s.country,
      }),
    });
  };

  const filtered = servers.filter(
    (s) =>
      !q ||
      s.country.toLowerCase().includes(q.toLowerCase()) ||
      s.countryShort.toLowerCase().includes(q.toLowerCase()) ||
      s.ip.includes(q) ||
      s.ddns.toLowerCase().includes(q.toLowerCase()) ||
      String(s.tcpPort).includes(q),
  );

  return (
    <Section title="VPN Gate directory (public free relays)">
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <button
          onClick={load}
          className="rounded-lg bg-sky-500 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-400"
        >
          {loading ? "Loading…" : "Refresh list"}
        </button>
        <input
          className={inputCls + " flex-1 min-w-[200px]"}
          placeholder="Filter by country or IP…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <span className="text-sm text-slate-500">
          {filtered.length} shown · user/pass = vpn/vpn · ports auto-detected
        </span>
      </div>
      {error && (
        <p className="mb-4 rounded-lg border border-amber-800 bg-amber-950/40 p-3 text-sm text-amber-300">
          {error}
        </p>
      )}
      <p className="mb-4 rounded-lg border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-400">
        Many SoftEther / VPN Gate servers do <b>not</b> run SSTP on port 443.
        The VPN Gate CSV has no SSTP-port field, so the port is decoded from each
        server&rsquo;s embedded OpenVPN config — non-443 ports are highlighted in{" "}
        <span className="text-amber-300">amber</span>. The client connects by IP
        with <code>-insecure</code>, so self-signed SoftEther certificates that
        the native Windows client rejects work fine here.
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr className="border-b border-slate-800">
              <th className="py-2 pr-3">Country</th>
              <th className="py-2 pr-3">SSTP host</th>
              <th className="py-2 pr-3">Port</th>
              <th className="py-2 pr-3">Speed</th>
              <th className="py-2 pr-3">Ping</th>
              <th className="py-2 pr-3">Sessions</th>
              <th className="py-2 pr-3">Uptime</th>
              <th className="py-2 pr-3"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((s) => (
              <tr
                key={s.ip + s.hostName}
                className="border-b border-slate-900 hover:bg-slate-900/50"
              >
                <td className="py-2 pr-3">{s.country}</td>
                <td className="py-2 pr-3 font-mono text-xs">
                  {s.ddns || s.ip}
                  <span className="block text-[10px] text-slate-500">
                    {s.ip}
                  </span>
                </td>
                <td className="py-2 pr-3">
                  <span
                    className={
                      s.tcpPort === 443
                        ? "text-slate-300"
                        : "font-semibold text-amber-300"
                    }
                  >
                    {s.tcpPort}
                  </span>
                </td>
                <td className="py-2 pr-3 text-emerald-300">
                  {s.speedMbps} Mbps
                </td>
                <td className="py-2 pr-3">{s.ping} ms</td>
                <td className="py-2 pr-3">{s.sessions}</td>
                <td className="py-2 pr-3">{s.uptimeHours} h</td>
                <td className="py-2 pr-3">
                  <div className="flex gap-2">
                    <button
                      onClick={() => onUse(s)}
                      className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                    >
                      Use
                    </button>
                    <button
                      onClick={() => save(s)}
                      className="rounded bg-slate-700 px-3 py-1 text-xs font-medium text-slate-200 hover:bg-slate-600"
                    >
                      Save
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && !loading && (
              <tr>
                <td colSpan={8} className="py-6 text-center text-slate-500">
                  No servers loaded. Try refresh, or enter one manually in the
                  command builder.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </Section>
  );
}

function SavedTab({ onUse }: { onUse: (s: SavedServer) => void }) {
  const [servers, setServers] = useState<SavedServer[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setError("");
    try {
      const res = await fetch("/api/servers");
      const data = await res.json();
      if (data.ok) setServers(data.servers);
      else setError(data.error);
    } catch (e) {
      setError((e as Error).message);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const remove = async (id: number) => {
    await fetch(`/api/servers/${id}`, { method: "DELETE" });
    load();
  };

  return (
    <Section title="Saved servers">
      {error && (
        <p className="mb-4 rounded-lg border border-amber-800 bg-amber-950/40 p-3 text-sm text-amber-300">
          {error}
        </p>
      )}
      {servers.length === 0 ? (
        <p className="text-sm text-slate-500">
          No saved servers yet. Save one from the command builder or VPN Gate
          directory.
        </p>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {servers.map((s) => (
            <div
              key={s.id}
              className="rounded-xl border border-slate-800 bg-slate-950/60 p-4"
            >
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-semibold text-slate-100">{s.name}</p>
                  <p className="font-mono text-xs text-slate-400">
                    {s.host}:{s.port}
                  </p>
                </div>
                {s.country && (
                  <span className="rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">
                    {s.country}
                  </span>
                )}
              </div>
              <p className="mt-2 text-xs text-slate-500">
                auth {s.auth} · user {s.username}
              </p>
              <div className="mt-3 flex gap-2">
                <button
                  onClick={() => onUse(s)}
                  className="rounded bg-sky-600 px-3 py-1 text-xs font-medium text-white hover:bg-sky-500"
                >
                  Use
                </button>
                <button
                  onClick={() => remove(s.id)}
                  className="rounded bg-rose-700/80 px-3 py-1 text-xs font-medium text-white hover:bg-rose-600"
                >
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </Section>
  );
}

function DownloadsTab() {
  const targets = [
    ["Linux", "amd64", "sstp-proxy-linux-amd64"],
    ["Linux", "arm64", "sstp-proxy-linux-arm64"],
    ["Windows", "amd64", "sstp-proxy-windows-amd64.exe"],
    ["Windows", "arm64", "sstp-proxy-windows-arm64.exe"],
    ["macOS", "amd64", "sstp-proxy-darwin-amd64"],
    ["macOS", "arm64", "sstp-proxy-darwin-arm64"],
  ];
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Section title="Build fully static binaries">
        <p className="mb-3 text-sm text-slate-400">
          The client is pure Go with <code>CGO_ENABLED=0</code>, so every target
          is a single static executable — no mingw, no emulator, no DLLs, no
          runtime dependencies.
        </p>
        <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-emerald-300">
{`cd client

# one-shot build for all platforms
./build.sh

# or a single target, e.g. Windows x64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \\
  go build -trimpath -ldflags "-s -w" \\
  -o dist/sstp-proxy-windows-amd64.exe .`}
        </pre>
      </Section>
      <Section title="Produced artifacts">
        <table className="w-full text-left text-sm">
          <thead className="text-slate-400">
            <tr className="border-b border-slate-800">
              <th className="py-2">OS</th>
              <th className="py-2">Arch</th>
              <th className="py-2">Binary</th>
            </tr>
          </thead>
          <tbody>
            {targets.map(([os, arch, file]) => (
              <tr key={file} className="border-b border-slate-900">
                <td className="py-2">{os}</td>
                <td className="py-2">{arch}</td>
                <td className="py-2 font-mono text-xs text-emerald-300">
                  {file}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="mt-3 text-xs text-slate-500">
          Verify with <code>go test ./...</code> — includes MS-SSTP crypto
          binding and MS-CHAPv2 spec-vector tests.
        </p>
      </Section>
    </div>
  );
}

function AboutTab() {
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      <Section title="Architecture">
        <pre className="overflow-x-auto rounded-lg bg-slate-950 p-4 text-xs text-slate-300">
{` browser ──SOCKS5/HTTP──▶ sstp-proxy
                              │
                              ▼
              gVisor userspace TCP/IP stack
                              │  (IP packets)
                              ▼
           PPP  (LCP · MS-CHAPv2/PAP · IPCP)
                              │  (PPP frames)
                              ▼
        SSTP control/data over TLS  (TCP/443)
                              │
                              ▼
   SoftEther / Windows RRAS / VPN Gate server`}
        </pre>
      </Section>
      <Section title="Why no system-wide VPN?">
        <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
          <li>
            The full IP stack runs in userspace (gVisor), so there is no TUN
            device and no change to your OS routing table.
          </li>
          <li>
            Only apps you point at the local SOCKS5/HTTP proxy use the tunnel —
            perfect for sending just one browser or profile through the VPN.
          </li>
          <li>No admin/root privileges required.</li>
          <li>DNS is resolved through the tunnel to avoid leaks.</li>
        </ul>
      </Section>
      <Section title="Protocol coverage">
        <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
          <li>SSTP handshake + control state machine over TLS.</li>
          <li>
            Crypto binding with HMAC-SHA1-160 &amp; HMAC-SHA256-256 (IKEv2 PRF+
            → CMK → Compound MAC).
          </li>
          <li>PPP LCP, MS-CHAPv2 / PAP / CHAP-MD5, IPCP (IP + DNS).</li>
          <li>MPPE master-key derivation (RFC 3079) for the HLAK.</li>
        </ul>
      </Section>
      <Section title="Verified end-to-end">
        <p className="text-sm text-slate-300">
          Beyond spec-vector unit tests, an in-process mock SoftEther-style SSTP
          server drives the <b>real client</b> through the entire pipeline in a
          race-clean integration test: SSTP handshake → crypto binding → PPP
          LCP/MS-CHAPv2/IPCP → dual userspace netstacks → an HTTP page fetched
          through the client&rsquo;s <b>SOCKS5 proxy</b>. The mock server
          independently recomputes and validates the client&rsquo;s
          crypto-binding Compound MAC, proving interoperability of the whole
          chain — not just isolated primitives.
        </p>
      </Section>
      <Section title="Compatibility">
        <p className="text-sm text-slate-300">
          Speaks the same wire protocol as the built-in Windows SSTP client, so
          it interoperates with <b>Windows Server RRAS</b>, <b>MikroTik
          RouterOS</b>, <b>SoftEther VPN Server</b> and the public{" "}
          <b>VPN Gate</b> academic relay network. Crypto binding and MS-CHAPv2
          are validated byte-for-byte against the Microsoft [MS-SSTP] and RFC
          2759 reference vectors.
        </p>
      </Section>
      <Section title="SoftEther / VPN Gate specifics">
        <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
          <li>
            <b>Non-standard ports.</b> SoftEther exposes SSTP on whatever TCP
            port the server listens on — frequently not 443. Just pass{" "}
            <code>host:port</code>; the panel auto-detects ports from VPN Gate.
          </li>
          <li>
            <b>Self-signed certs.</b> SoftEther&rsquo;s SSTP clone usually uses a
            self-signed certificate that the native Windows client refuses. Use{" "}
            <code>-insecure</code> (default) to connect by IP without importing a
            cert.
          </li>
          <li>
            <b>Virtual hubs.</b> SoftEther routes an SSTP session to a hub chosen
            from the PPP username. Use <code>-hub NAME</code> (sent as{" "}
            <code>user@NAME</code>). VPN Gate&rsquo;s hub is <code>vpngate</code>.
          </li>
          <li>
            <b>20-second idle timeout.</b> SoftEther drops idle SSTP sessions, so
            the client sends an SSTP echo keepalive every 8&nbsp;s and can
            auto-reconnect with <code>-retry</code>.
          </li>
          <li>
            <b>Censorship — proxy.</b> If a direct connection to the server is
            blocked, tunnel the SSTP connection through an upstream proxy with{" "}
            <code>-proxy socks5://…</code> or <code>-proxy http://…</code>{" "}
            (SOCKS5 and HTTP/HTTPS CONNECT, optional <code>user:pass@</code>).
          </li>
          <li>
            <b>Censorship — DPI evasion.</b> Defeat TLS-fingerprint (JA3)
            blocking by mimicking a real browser ClientHello with{" "}
            <code>-fingerprint chrome</code> (also firefox/safari/edge/ios/
            android/random). Dodge SNI-based DPI with <code>-sni -</code> (no
            SNI) or a decoy value, and do domain fronting with{" "}
            <code>-connect</code> + <code>-sni</code> + <code>-host-header</code>.
            All combine with <code>-proxy</code>.
          </li>
        </ul>
      </Section>
    </div>
  );
}
