import { motion } from "framer-motion";

const TypingIndicator = () => (
  <div className="flex items-center gap-2 px-4 py-3">
    <div className="flex items-center gap-1.5 bg-card border border-border rounded-2xl rounded-bl-md px-4 py-3">
      <span className="text-xs text-primary font-mono mr-2">Analyzing logs</span>
      {[0, 1, 2].map((i) => (
        <motion.div
          key={i}
          className="h-1.5 w-1.5 rounded-full bg-primary"
          animate={{ opacity: [0.3, 1, 0.3] }}
          transition={{ duration: 1, repeat: Infinity, delay: i * 0.2 }}
        />
      ))}
    </div>
  </div>
);

export default TypingIndicator;
