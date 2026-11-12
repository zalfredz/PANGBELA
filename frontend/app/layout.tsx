import type { Metadata } from "next";
import Link from "next/link";
import "./globals.css";

export const metadata: Metadata = {
  title: "PANGBELA",
  description: "Pertahanan lab: serangan diperiksa agen, diputuskan aturan, ditangani PAMELA atau Anda",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="id" className="h-full antialiased">
      <body className="flex min-h-full flex-col">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-0 focus:flex focus:min-h-11 focus:items-center focus:bg-surface focus:px-3"
        >
          Langsung ke isi
        </a>
        <header className="border-b border-line bg-surface">
          <nav aria-label="Utama" className="mx-auto flex max-w-5xl items-center gap-1 px-4">
            <Link
              href="/incidents"
              className="mr-4 flex min-h-11 items-center text-sm font-bold tracking-widest"
            >
              PANGBELA
            </Link>
            <Link
              href="/incidents"
              className="flex min-h-11 items-center px-3 text-sm text-muted hover:text-ink"
            >
              Dasbor
            </Link>
            <Link
              href="/tests"
              className="flex min-h-11 items-center px-3 text-sm text-muted hover:text-ink"
            >
              Uji skenario
            </Link>
          </nav>
        </header>
        <main id="main" className="mx-auto w-full max-w-5xl flex-1 px-4 py-6">
          {children}
        </main>
      </body>
    </html>
  );
}
