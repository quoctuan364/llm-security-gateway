import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Aegis LLM Security Gateway & Privacy Firewall",
  description: "Next-Generation Production Guardrails, PII Sanitization, and Active LLM Firewall",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased bg-[#090d16] text-slate-100 selection:bg-cyan-500/30">
        {children}
      </body>
    </html>
  );
}
