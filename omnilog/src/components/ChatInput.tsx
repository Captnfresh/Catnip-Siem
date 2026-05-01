import { useState, useRef, useEffect } from "react";
import { Send, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ChatInputProps {
  onSend: (message: string) => void;
  isLoading: boolean;
  externalValue?: string;
  onExternalValueConsumed?: () => void;
}

const demoQueries = [
  "What happened in the last 10 minutes?",
  "Show failed login attempts",
  "Any critical threats detected?",
  "Show network activity",
];

const ChatInput = ({ onSend, isLoading, externalValue, onExternalValueConsumed }: ChatInputProps) => {
  const [input, setInput] = useState("");
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    if (externalValue) {
      setInput(externalValue);
      onExternalValueConsumed?.();
      inputRef.current?.focus();
    }
  }, [externalValue, onExternalValueConsumed]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;
    onSend(trimmed);
    setInput("");
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div className="border-t border-border bg-card/50 backdrop-blur-sm p-4 space-y-3">
      {/* Demo Queries */}
      <div className="flex flex-wrap gap-2">
        {demoQueries.map((q) => (
          <button
            key={q}
            onClick={() => onSend(q)}
            disabled={isLoading}
            className="text-xs font-mono px-3 py-1.5 rounded-full border border-border bg-muted/50 text-muted-foreground hover:text-primary hover:border-primary/30 transition-colors disabled:opacity-50"
          >
            <Zap className="h-3 w-3 inline mr-1" />
            {q}
          </button>
        ))}
      </div>

      {/* Input Area */}
      <div className="flex items-end gap-2">
        <textarea
          ref={inputRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Ask OmniLog about your security logs..."
          rows={1}
          className="flex-1 resize-none bg-muted border border-border rounded-xl px-4 py-3 text-sm text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary/50 focus:border-primary/50 transition-all font-mono"
        />
        <Button
          onClick={handleSend}
          disabled={!input.trim() || isLoading}
          size="icon"
          className="h-11 w-11 rounded-xl bg-primary text-primary-foreground hover:bg-primary/90 glow-primary"
        >
          <Send className="h-4 w-4" />
        </Button>
      </div>
    </div>
  );
};

export default ChatInput;
