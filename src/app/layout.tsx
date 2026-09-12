import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

export const metadata: Metadata = {
  title: "sstp-proxy · SSTP → SOCKS/HTTP control panel",
  description:
    "Control panel and command builder for sstp-proxy, a standalone SSTP (SoftEther / VPN Gate) client that exposes local SOCKS5 and HTTP proxies.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="bg-slate-950 text-slate-100 antialiased">{children}</body>
    </html>
  );
}
