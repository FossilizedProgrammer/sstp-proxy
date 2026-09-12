export const dynamic = "force-dynamic";
export const revalidate = 0;

export type VpnGateServer = {
  hostName: string;
  ddns: string; // DDNS hostname (xxx.opengw.net) when available
  ip: string;
  country: string;
  countryShort: string;
  speedMbps: number;
  ping: string;
  sessions: number;
  score: number;
  uptimeHours: number;
  tcpPort: number; // discovered SSTP/SSL-VPN TCP port (443 or a random one)
  sstpHost: string; // ready-to-use host:port for the sstp-proxy -server flag
};

const MIRRORS = [
  "https://www.vpngate.net/api/iphone/",
  "http://www.vpngate.net/api/iphone/",
  "https://vpngate.4d.workers.dev/api/iphone/",
];

async function fetchCsv(): Promise<string> {
  let lastErr: unknown;
  for (const url of MIRRORS) {
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 12000);
      const res = await fetch(url, {
        signal: ctrl.signal,
        cache: "no-store",
        headers: { "User-Agent": "sstp-proxy-panel/1.0" },
      });
      clearTimeout(t);
      if (res.ok) return await res.text();
      lastErr = new Error(`status ${res.status}`);
    } catch (err) {
      lastErr = err;
    }
  }
  throw lastErr ?? new Error("all mirrors failed");
}

// VPN Gate's CSV has NO dedicated SSTP port column. The SSTP endpoint listens
// on the server's main TCP port, which is embedded in the base64 OpenVPN config
// as `remote <ip> <port>`. We decode it to recover the true port (often not
// 443). This is what makes non-standard-port SoftEther/VPN Gate servers usable.
function portFromOpenVPN(b64: string): number {
  try {
    const cfg = Buffer.from(b64, "base64").toString("utf8");
    // Prefer a TCP remote; fall back to the first remote line.
    const lines = cfg.split(/\r?\n/);
    let tcpPort = 0;
    let anyPort = 0;
    let proto = "";
    for (const raw of lines) {
      const line = raw.trim();
      if (line.startsWith("proto ")) proto = line.slice(6).trim().toLowerCase();
      if (line.startsWith("remote ")) {
        const parts = line.split(/\s+/);
        const p = Number(parts[2]);
        if (Number.isFinite(p) && p > 0 && p < 65536) {
          if (anyPort === 0) anyPort = p;
          const lineProto = (parts[3] || proto).toLowerCase();
          if (lineProto.includes("tcp") && tcpPort === 0) tcpPort = p;
        }
      }
    }
    return tcpPort || anyPort || 0;
  } catch {
    return 0;
  }
}

export async function GET() {
  try {
    const csv = await fetchCsv();
    const lines = csv.split(/\r?\n/);
    const servers: VpnGateServer[] = [];
    for (const line of lines) {
      if (!line || line.startsWith("*") || line.startsWith("#")) continue;
      const cols = line.split(",");
      if (cols.length < 15) continue;
      const ip = cols[1];
      if (!ip) continue;
      const speed = Number(cols[4]) || 0;
      const port = portFromOpenVPN(cols[14]) || 443;
      // VPN Gate exposes an SSTP DDNS hostname of the form <hostName>.opengw.net.
      const hostName = cols[0];
      const ddns = hostName ? `${hostName}.opengw.net` : "";
      const base = ddns || ip;
      const sstpHost = port === 443 ? base : `${base}:${port}`;
      servers.push({
        hostName,
        ddns,
        ip,
        country: cols[5] || "Unknown",
        countryShort: cols[6] || "",
        speedMbps: Math.round((speed / 1_000_000) * 10) / 10,
        ping: cols[3] || "-",
        sessions: Number(cols[7]) || 0,
        score: Number(cols[2]) || 0,
        uptimeHours: Math.round((Number(cols[8]) || 0) / 3_600_000),
        tcpPort: port,
        sstpHost,
      });
    }
    servers.sort((a, b) => b.speedMbps - a.speedMbps);
    return Response.json({
      ok: true,
      count: servers.length,
      servers: servers.slice(0, 150),
    });
  } catch (err) {
    return Response.json(
      {
        ok: false,
        error:
          "Could not reach the VPN Gate directory (" +
          (err as Error).message +
          "). This environment may block outbound access; you can still enter a server manually.",
        servers: [],
      },
      { status: 200 },
    );
  }
}
