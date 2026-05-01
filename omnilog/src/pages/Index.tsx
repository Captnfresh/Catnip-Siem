import { useState, useCallback } from "react";
import { SidebarProvider } from "@/components/ui/sidebar";
import AppSidebar from "@/components/AppSidebar";
import TopBar from "@/components/TopBar";
import ChatArea from "@/components/ChatArea";

const Index = () => {
  const [pendingQuery, setPendingQuery] = useState<string | null>(null);

  const handleQuickFilter = useCallback((query: string) => {
    setPendingQuery(query);
  }, []);

  const handleQueryConsumed = useCallback(() => {
    setPendingQuery(null);
  }, []);

  return (
    <SidebarProvider>
      <div className="min-h-screen flex w-full">
        <AppSidebar onQuickFilter={handleQuickFilter} />
        <div className="flex-1 flex flex-col min-h-screen">
          <TopBar isConnected={true} />
          <ChatArea pendingQuery={pendingQuery} onQueryConsumed={handleQueryConsumed} />
        </div>
      </div>
    </SidebarProvider>
  );
};

export default Index;
