import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { reportData } from '@/data/reportData';
import { Shield, Brain, Zap } from 'lucide-react';

export function MetricsOverview() {
  const { sonarqube, claude_opus, claude_sonnet } = reportData;

  const cards = [
    {
      title: 'SonarQube Enterprise',
      icon: Shield,
      color: 'text-blue-500',
      bgColor: 'bg-blue-500/10',
      metrics: sonarqube.overall_metrics,
      detected: sonarqube.vulnerabilities_detected,
    },
    {
      title: 'Claude Opus 4.1',
      icon: Brain,
      color: 'text-red-500',
      bgColor: 'bg-red-500/10',
      metrics: claude_opus.overall_metrics,
      detected: claude_opus.vulnerabilities_detected,
      cost: claude_opus.cost_metrics,
    },
    {
      title: 'Claude Sonnet 4',
      icon: Zap,
      color: 'text-teal-500',
      bgColor: 'bg-teal-500/10',
      metrics: claude_sonnet.overall_metrics,
      detected: claude_sonnet.vulnerabilities_detected,
      cost: claude_sonnet.cost_metrics,
    },
  ];

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {cards.map((card) => (
        <Card key={card.title} className="border-l-4 border-l-current">
          <CardHeader className="pb-2">
            <div className="flex items-center gap-2">
              <div className={`p-2 rounded-lg ${card.bgColor}`}>
                <card.icon className={`w-5 h-5 ${card.color}`} />
              </div>
              <CardTitle className="text-sm font-medium">{card.title}</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-2xl font-bold">{card.metrics.f1_score.toFixed(4)}</div>
                <div className="text-xs text-muted-foreground">F1 Score</div>
              </div>
              <div>
                <div className="text-2xl font-bold">{card.metrics.recall.toFixed(4)}</div>
                <div className="text-xs text-muted-foreground">Recall</div>
              </div>
              <div>
                <div className="text-2xl font-bold">{card.metrics.precision.toFixed(4)}</div>
                <div className="text-xs text-muted-foreground">Precision</div>
              </div>
              <div>
                <div className="text-2xl font-bold">{card.detected}/{reportData.metadata.dataset_stats.vulnerable_count}</div>
                <div className="text-xs text-muted-foreground">Detected</div>
              </div>
            </div>
            {card.cost && (
              <div className="mt-3 pt-3 border-t text-xs text-muted-foreground">
                Cost: ${card.cost.total_cost_usd.toFixed(4)} (${card.cost.cost_per_vulnerability_found?.toFixed(4) || 'N/A'}/vuln)
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
