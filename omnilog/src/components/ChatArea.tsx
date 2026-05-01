import { useState, useRef, useEffect, useCallback } from "react";
import { Shield } from "lucide-react";
import ChatMessage, { type Message } from "./ChatMessage";
import ChatInput from "./ChatInput";
import TypingIndicator from "./TypingIndicator";
import { fetchAnalysis } from "@/lib/api";

interface ChatAreaProps {
  pendingQuery: string | null;
  onQueryConsumed: () => void;
}

const ChatArea = ({ pendingQuery, onQueryConsumed }: ChatAreaProps) => {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [sessionId, setSessionId] = useState<string | undefined>(undefined);
  const scrollRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const handleSend = useCallback(
    (content: string) => {
      const userMsg: Message = {
        id: crypto.randomUUID(),
        role: "user",
        content,
        timestamp: new Date(),
      };
      setMessages((prev) => [...prev, userMsg]);
      setIsLoading(true);

      fetchAnalysis(content, sessionId).then((analysis) => {
        // Persist session ID for multi-turn context
        if (analysis.sessionId) {
          setSessionId(analysis.sessionId);
        }

        const isZeroDay = analysis.mlPrediction?.isZeroDay ?? false;
        const defaultReply = isZeroDay
          ? "⚠️ Zero-day anomaly detected. OmniLog's ML engine flagged behaviour that matches no known attack signature. Treat with high priority:"
          : "I've analyzed the recent security logs based on your query. Here's what I found:";

        const aiMsg: Message = {
          id: crypto.randomUUID(),
          role: "assistant",
          content: analysis.conversationalReply || defaultReply,
          timestamp: new Date(),
          analysis,
        };
        setMessages((prev) => [...prev, aiMsg]);
        setIsLoading(false);
      });
    },
    [sessionId],
  );

  // Handle external queries from sidebar
  useEffect(() => {
    if (pendingQuery) {
      handleSend(pendingQuery);
      onQueryConsumed();
    }
  }, [pendingQuery, onQueryConsumed, handleSend]);

  return (
    <div className="flex-1 flex flex-col min-h-0">
      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto bg-grid">
        {messages.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-4 space-y-4">
            <div className="h-16 w-16 rounded-2xl bg-primary/10 border border-primary/20 flex items-center justify-center glow-primary">
              <Shield className="h-8 w-8 text-primary" />
            </div>
            <div>
              <h2 className="text-xl font-semibold text-foreground mb-1">Welcome to OmniLog</h2>
              <p className="text-sm text-muted-foreground max-w-md">
                Your AI-powered SIEM assistant. Ask me about security events, failed logins,
                network anomalies, or any threats detected in your environment.
              </p>
            </div>
            <div className="font-mono text-xs text-muted-foreground/50">
              Graylog Integration • Real-time Analysis • Threat Intelligence
            </div>
          </div>
        ) : (
          <div className="py-4">
            {messages.map((msg) => (
              <ChatMessage key={msg.id} message={msg} />
            ))}
            {isLoading && <TypingIndicator />}
          </div>
        )}
      </div>

      {/* Input */}
      <ChatInput onSend={handleSend} isLoading={isLoading} />
    </div>
  );
};

export default ChatArea;
