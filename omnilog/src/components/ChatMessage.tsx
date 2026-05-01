import { motion } from "framer-motion";
import { User, Shield } from "lucide-react";
import ThreatCard from "./ThreatCard";
import type { ThreatAnalysis } from "@/lib/mock-logs";

export interface Message {
  id: string;
  role: "user" | "assistant";
  content: string;
  timestamp: Date;
  analysis?: ThreatAnalysis;
}

interface ChatMessageProps {
  message: Message;
}

const ChatMessage = ({ message }: ChatMessageProps) => {
  const isUser = message.role === "user";

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className={`flex gap-3 px-4 py-3 ${isUser ? "justify-end" : ""}`}
    >
      {!isUser && (
        <div className="h-8 w-8 rounded-lg bg-primary/10 border border-primary/20 flex items-center justify-center shrink-0 mt-0.5">
          <Shield className="h-4 w-4 text-primary" />
        </div>
      )}

      <div className={`max-w-[80%] space-y-2 ${isUser ? "items-end" : ""}`}>
        <div
          className={`rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
            isUser
              ? "bg-primary text-primary-foreground rounded-br-md"
              : "bg-card border border-border rounded-bl-md"
          }`}
        >
          {message.content}
        </div>

        {message.analysis && <ThreatCard analysis={message.analysis} />}

        <span className="text-[10px] font-mono text-muted-foreground block px-1">
          {message.timestamp.toLocaleTimeString()}
        </span>
      </div>

      {isUser && (
        <div className="h-8 w-8 rounded-lg bg-secondary border border-border flex items-center justify-center shrink-0 mt-0.5">
          <User className="h-4 w-4 text-muted-foreground" />
        </div>
      )}
    </motion.div>
  );
};

export default ChatMessage;
