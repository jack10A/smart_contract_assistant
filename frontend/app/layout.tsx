import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ChainSentinel AI — Security Console",
  description: "AI-powered smart contract security assistant and blockchain investigation platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark h-full">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap"
          rel="stylesheet"
        />
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@20..48,100..700,0..1,-50..200"
          rel="stylesheet"
        />
      </head>
      <body className="h-full overflow-hidden bg-surface text-on-surface antialiased">
        {children}
      </body>
    </html>
  );
}
