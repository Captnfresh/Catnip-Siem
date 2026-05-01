import { motion } from "framer-motion";

interface RiskGaugeProps {
  score: number;
}

const RiskGauge = ({ score }: RiskGaugeProps) => {
  const getColor = () => {
    if (score < 30) return "text-accent";
    if (score < 60) return "text-warning";
    return "text-destructive";
  };

  const getBgColor = () => {
    if (score < 30) return "bg-accent/20";
    if (score < 60) return "bg-warning/20";
    return "bg-destructive/20";
  };

  const getBarColor = () => {
    if (score < 30) return "bg-accent";
    if (score < 60) return "bg-warning";
    return "bg-destructive";
  };

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground font-mono">RISK SCORE</span>
        <span className={`text-xl font-bold font-mono ${getColor()}`}>{score}</span>
      </div>
      <div className={`h-2 rounded-full ${getBgColor()}`}>
        <motion.div
          className={`h-full rounded-full ${getBarColor()}`}
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 1, ease: "easeOut" }}
        />
      </div>
    </div>
  );
};

export default RiskGauge;
