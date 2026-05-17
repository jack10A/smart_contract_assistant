"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const navItems = [
  { href: "/workspace",          icon: "workspaces",        label: "Workspace" },
  { href: "/dashboard",          icon: "dashboard",         label: "Risk Dashboard" },
  { href: "/audit",              icon: "security",          label: "Smart Contract Audit" },
  { href: "/findings",           icon: "bug_report",        label: "Vulnerability Findings" },
  { href: "/structured-findings",icon: "list_alt",          label: "Structured Findings" },
  { href: "/attack-replay",      icon: "history_edu",       label: "Attack Replay" },
  { href: "/line-evidence",      icon: "terminal",          label: "Line Evidence" },
  { href: "/function-analysis",  icon: "account_tree",      label: "Function Analysis" },
  { href: "/csv-anomaly",        icon: "table_rows",        label: "CSV Anomaly Detection" },
  { href: "/json-trace",         icon: "schema",            label: "JSON Trace Analysis" },
  { href: "/image-security",     icon: "image_search",      label: "Image Security Analysis" },
  { href: "/multi-agent",        icon: "hub",               label: "Multi-Agent Investigation" },
  { href: "/chat",               icon: "smart_toy",         label: "Source-Grounded Chat" },
  { href: "/reports",            icon: "description",       label: "Reports" },
  { href: "/audit-history",      icon: "manage_history",    label: "Audit History" },
  { href: "/settings",           icon: "settings",          label: "Settings" },
];

export default function Sidebar() {
  const pathname = usePathname();

  return (
    <aside
      className="hidden md:flex flex-col h-screen w-64 shrink-0 py-4"
      style={{ backgroundColor: "#141b2b", borderRight: "1px solid #424754" }}
    >
      {/* Brand */}
      <div className="px-6 mb-4">
        <h1
          className="font-headline-sm text-headline-sm font-bold tracking-tight"
          style={{ color: "#adc6ff" }}
        >
          ChainSentinel
        </h1>
        <p className="font-label-caps text-label-caps" style={{ color: "#c2c6d6" }}>
          Vigilance Engine v2.4
        </p>
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto px-2 space-y-0.5">
        {navItems.map((item) => {
          const isActive = pathname === item.href || pathname.startsWith(item.href + "/");
          return (
            <Link
              key={item.href}
              href={item.href}
              className={[
                "flex items-center px-3 py-2 mx-0.5 rounded-lg transition-all duration-100 group",
                isActive
                  ? "nav-active"
                  : "text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface",
              ].join(" ")}
            >
              <span
                className="material-symbols-outlined mr-3 text-sm"
                style={{ fontSize: "18px" }}
              >
                {item.icon}
              </span>
              <span className="font-label-caps text-label-caps">{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* New Audit CTA */}
      <div className="px-4 py-3">
        <button
          className="w-full py-2 font-label-caps text-label-caps font-bold flex items-center justify-center gap-2 rounded-lg active:scale-95 transition-transform duration-100"
          style={{ backgroundColor: "#adc6ff", color: "#002e6a" }}
        >
          <span className="material-symbols-outlined text-sm" style={{ fontSize: "16px" }}>
            add
          </span>
          New Audit
        </button>
      </div>

      {/* Footer */}
      <div className="border-t pt-3 px-2 space-y-0.5" style={{ borderColor: "#424754" }}>
        <Link
          href="/docs"
          className="flex items-center px-3 py-2 rounded transition-colors text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface"
        >
          <span className="material-symbols-outlined mr-3" style={{ fontSize: "18px" }}>help</span>
          <span className="font-label-caps text-label-caps">Documentation</span>
        </Link>
        <Link
          href="/support"
          className="flex items-center px-3 py-2 rounded transition-colors text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface"
        >
          <span className="material-symbols-outlined mr-3" style={{ fontSize: "18px" }}>contact_support</span>
          <span className="font-label-caps text-label-caps">Support</span>
        </Link>
        {/* User */}
        <div className="flex items-center px-3 py-2 mt-2 gap-3">
          <div
            className="w-8 h-8 rounded flex items-center justify-center shrink-0"
            style={{ backgroundColor: "#4d8eff", color: "#00285d" }}
          >
            <span className="material-symbols-outlined" style={{ fontSize: "16px" }}>admin_panel_settings</span>
          </div>
          <div>
            <p className="font-label-caps text-label-caps text-on-surface">Sentinel Admin</p>
            <p style={{ fontSize: "10px", color: "#c2c6d6" }}>Active Session</p>
          </div>
        </div>
      </div>
    </aside>
  );
}
