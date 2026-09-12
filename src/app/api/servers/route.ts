import { db } from "@/db";
import { savedServers } from "@/db/schema";
import { desc } from "drizzle-orm";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const rows = await db
      .select()
      .from(savedServers)
      .orderBy(desc(savedServers.createdAt));
    return Response.json({ ok: true, servers: rows });
  } catch (err) {
    return Response.json(
      { ok: false, error: (err as Error).message },
      { status: 500 },
    );
  }
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const host = String(body.host ?? "").trim();
    if (!host) {
      return Response.json(
        { ok: false, error: "host is required" },
        { status: 400 },
      );
    }
    const port = Number.isFinite(Number(body.port)) ? Number(body.port) : 443;
    const [row] = await db
      .insert(savedServers)
      .values({
        name: String(body.name ?? host).trim() || host,
        host,
        port,
        username: String(body.username ?? "vpn").trim() || "vpn",
        password: String(body.password ?? "vpn"),
        country: String(body.country ?? "").trim(),
        auth: String(body.auth ?? "auto").trim() || "auto",
        socksAddr: String(body.socksAddr ?? "127.0.0.1:1080").trim(),
        httpAddr: String(body.httpAddr ?? "127.0.0.1:8080").trim(),
        notes: String(body.notes ?? "").trim(),
      })
      .returning();
    return Response.json({ ok: true, server: row });
  } catch (err) {
    return Response.json(
      { ok: false, error: (err as Error).message },
      { status: 500 },
    );
  }
}
