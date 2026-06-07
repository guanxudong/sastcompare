import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { reportData } from '@/data/reportData';
import { Badge } from '@/components/ui/badge';

export function DetailedTable() {
  const { sonarqube, claude_opus, claude_sonnet } = reportData;

  const scanners = [
    { name: 'SonarQube Enterprise', data: sonarqube, color: 'bg-blue-500' },
    { name: 'Claude Opus 4.1', data: claude_opus, color: 'bg-red-500' },
    { name: 'Claude Sonnet 4', data: claude_sonnet, color: 'bg-teal-500' },
  ];

  const metrics = [
    { key: 'precision', label: 'Precision', format: (v: number) => (v * 100).toFixed(2) + '%' },
    { key: 'recall', label: 'Recall', format: (v: number) => (v * 100).toFixed(2) + '%' },
    { key: 'f1_score', label: 'F1 Score', format: (v: number) => v.toFixed(4) },
    { key: 'accuracy', label: 'Accuracy', format: (v: number) => (v * 100).toFixed(2) + '%' },
    { key: 'false_positive_rate', label: 'False Positive Rate', format: (v: number) => (v * 100).toFixed(2) + '%' },
    { key: 'false_negative_rate', label: 'False Negative Rate', format: (v: number) => (v * 100).toFixed(2) + '%' },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Detailed Metrics Comparison</CardTitle>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Metric</TableHead>
              {scanners.map((s) => (
                <TableHead key={s.name} className="text-center">
                  <div className="flex items-center justify-center gap-2">
                    <div className={`w-3 h-3 rounded-full ${s.color}`} />
                    {s.name}
                  </div>
                </TableHead>
              ))}
            </TableRow>
          </TableHeader>
          <TableBody>
            {metrics.map((m) => (
              <TableRow key={m.key}>
                <TableCell className="font-medium">{m.label}</TableCell>
                {scanners.map((s) => {
                  const val = s.data.overall_metrics[m.key as keyof typeof s.data.overall_metrics] as number;
                  const isBest = scanners.every((other) => {
                    const otherVal = other.data.overall_metrics[m.key as keyof typeof other.data.overall_metrics] as number;
                    return m.key.includes('false') ? val <= otherVal : val >= otherVal;
                  });
                  return (
                    <TableCell key={s.name} className="text-center">
                      <div className="flex items-center justify-center gap-2">
                        <span className={isBest ? 'font-bold text-green-600' : ''}>
                          {m.format(val)}
                        </span>
                        {isBest && <Badge variant="outline" className="text-green-600 border-green-600">Best</Badge>}
                      </div>
                    </TableCell>
                  );
                })}
              </TableRow>
            ))}
            <TableRow className="bg-muted/50">
              <TableCell className="font-medium">Vulns Detected</TableCell>
              {scanners.map((s) => (
                <TableCell key={s.name} className="text-center font-bold">
                  {s.data.vulnerabilities_detected} / {s.data.vulnerable_samples}
                </TableCell>
              ))}
            </TableRow>
            <TableRow>
              <TableCell className="font-medium">Total Cost</TableCell>
              <TableCell className="text-center text-muted-foreground">Subscription</TableCell>
              <TableCell className="text-center">
                ${claude_opus.cost_metrics?.total_cost_usd.toFixed(4)}
              </TableCell>
              <TableCell className="text-center">
                ${claude_sonnet.cost_metrics?.total_cost_usd.toFixed(4)}
              </TableCell>
            </TableRow>
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
