import Sidebar from "../components/Sidebar";
import TopHeader from "../components/TopHeader";
import { SessionProvider } from "../context/SessionContext";

export default function DashboardLayout({ children }: { children: React.ReactNode }) {
  return (
    <SessionProvider>
      <div className="flex h-screen overflow-hidden bg-surface">
        <Sidebar />
        <main className="flex-1 flex flex-col min-w-0 overflow-hidden">
          <TopHeader />
          <div className="flex-1 overflow-y-auto">
            {children}
          </div>
        </main>
      </div>
    </SessionProvider>
  );
}
