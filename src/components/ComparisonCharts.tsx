import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
  RadarChart, PolarGrid, PolarAngleAxis, PolarRadiusAxis, Radar,
  PieChart, Pie, Cell
} from 'recharts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { reportData } from '@/data/reportData';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export function ComparisonCharts() {
  const { sonarqube, claude_opus, claude_sonnet, metadata } = reportData;
  const ds = metadata.dataset_stats;

  // Radar chart data
  const radarData = [
    { metric: 'Precision', SonarQube: sonarqube.overall_metrics.precision, 'Claude Opus': claude_opus.overall_metrics.precision, 'Claude Sonnet': claude_sonnet.overall_metrics.precision },
    { metric: 'Recall', SonarQube: sonarqube.overall_metrics.recall, 'Claude Opus': claude_opus.overall_metrics.recall, 'Claude Sonnet': claude_sonnet.overall_metrics.recall },
    { metric: 'F1 Score', SonarQube: sonarqube.overall_metrics.f1_score, 'Claude Opus': claude_opus.overall_metrics.f1_score, 'Claude Sonnet': claude_sonnet.overall_metrics.f1_score },
    { metric: 'Accuracy', SonarQube: sonarqube.overall_metrics.accuracy, 'Claude Opus': claude_opus.overall_metrics.accuracy, 'Claude Sonnet': claude_sonnet.overall_metrics.accuracy },
    { metric: '1-FPR', SonarQube: 1 - sonarqube.overall_metrics.false_positive_rate, 'Claude Opus': 1 - claude_opus.overall_metrics.false_positive_rate, 'Claude Sonnet': 1 - claude_sonnet.overall_metrics.false_positive_rate },
  ];

  // Bar chart data
  const barData = [
    { name: 'Precision', 'SonarQube': sonarqube.overall_metrics.precision, 'Claude Opus 4.1': claude_opus.overall_metrics.precision, 'Claude Sonnet 4': claude_sonnet.overall_metrics.precision },
    { name: 'Recall', 'SonarQube': sonarqube.overall_metrics.recall, 'Claude Opus 4.1': claude_opus.overall_metrics.recall, 'Claude Sonnet 4': claude_sonnet.overall_metrics.recall },
    { name: 'F1 Score', 'SonarQube': sonarqube.overall_metrics.f1_score, 'Claude Opus 4.1': claude_opus.overall_metrics.f1_score, 'Claude Sonnet 4': claude_sonnet.overall_metrics.f1_score },
    { name: 'Accuracy', 'SonarQube': sonarqube.overall_metrics.accuracy, 'Claude Opus 4.1': claude_opus.overall_metrics.accuracy, 'Claude Sonnet 4': claude_sonnet.overall_metrics.accuracy },
  ];

  // Language distribution
  const langData = Object.entries(ds.language_distribution).map(([name, value]) => ({ name, value }));
  const LANG_COLORS = ['#4C9AFF', '#FF6B6B', '#4ECDC4', '#FFE66D', '#95E1D3'];

  // CWE distribution
  const cweData = Object.entries(ds.cwe_distribution).map(([name, value]) => ({ name, value }));

  // Vuln type data
  const vulnTypeData = Object.entries(ds.vuln_type_distribution).map(([name, value]) => ({ name, value }));

  // Cost comparison
  const costData = [
    { name: 'Total Cost ($)', 'Claude Opus': claude_opus.cost_metrics?.total_cost_usd || 0, 'Claude Sonnet': claude_sonnet.cost_metrics?.total_cost_usd || 0 },
    { name: 'Cost/Vuln ($)', 'Claude Opus': claude_opus.cost_metrics?.cost_per_vulnerability_found || 0, 'Claude Sonnet': claude_sonnet.cost_metrics?.cost_per_vulnerability_found || 0 },
  ];

  return (
    <Tabs defaultValue="radar" className="w-full">
      <TabsList className="grid w-full grid-cols-4">
        <TabsTrigger value="radar">Performance Radar</TabsTrigger>
        <TabsTrigger value="metrics">Metrics Bar Chart</TabsTrigger>
        <TabsTrigger value="dataset">Dataset Distribution</TabsTrigger>
        <TabsTrigger value="cost">Cost Analysis</TabsTrigger>
      </TabsList>

      <TabsContent value="radar">
        <Card>
          <CardHeader>
            <CardTitle>Performance Comparison (Radar)</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={400}>
              <RadarChart cx="50%" cy="50%" outerRadius="80%" data={radarData}>
                <PolarGrid />
                <PolarAngleAxis dataKey="metric" />
                <PolarRadiusAxis angle={30} domain={[0, 1]} />
                <Radar name="SonarQube" dataKey="SonarQube" stroke="#4C9AFF" fill="#4C9AFF" fillOpacity={0.1} />
                <Radar name="Claude Opus" dataKey="Claude Opus" stroke="#FF6B6B" fill="#FF6B6B" fillOpacity={0.1} />
                <Radar name="Claude Sonnet" dataKey="Claude Sonnet" stroke="#4ECDC4" fill="#4ECDC4" fillOpacity={0.1} />
                <Legend />
                <Tooltip />
              </RadarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="metrics">
        <Card>
          <CardHeader>
            <CardTitle>Detection Metrics Comparison</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={400}>
              <BarChart data={barData} margin={{ top: 20, right: 30, left: 20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="name" />
                <YAxis domain={[0, 1]} />
                <Tooltip />
                <Legend />
                <Bar dataKey="SonarQube" fill="#4C9AFF" />
                <Bar dataKey="Claude Opus 4.1" fill="#FF6B6B" />
                <Bar dataKey="Claude Sonnet 4" fill="#4ECDC4" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </TabsContent>

      <TabsContent value="dataset">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Card>
            <CardHeader><CardTitle>Language Distribution</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie data={langData} cx="50%" cy="50%" outerRadius={80} dataKey="value" label>
                    {langData.map((_, index) => (
                      <Cell key={`cell-${index}`} fill={LANG_COLORS[index % LANG_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>CWE Distribution</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={cweData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={80} style={{ fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#4C9AFF" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Vulnerability Types</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={250}>
                <BarChart data={vulnTypeData} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis type="number" />
                  <YAxis dataKey="name" type="category" width={100} style={{ fontSize: 10 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#4ECDC4" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </div>
      </TabsContent>

      <TabsContent value="cost">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader><CardTitle>Cost Comparison</CardTitle></CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={costData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="name" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="Claude Opus" fill="#FF6B6B" />
                  <Bar dataKey="Claude Sonnet" fill="#4ECDC4" />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
          <Card>
            <CardHeader><CardTitle>Cost Efficiency Summary</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div className="p-4 bg-red-500/10 rounded-lg">
                <div className="font-semibold text-red-600">Claude Opus 4.1</div>
                <div className="text-sm text-muted-foreground mt-1">
                  Total: ${claude_opus.cost_metrics?.total_cost_usd.toFixed(4)}<br/>
                  Per vulnerability: ${claude_opus.cost_metrics?.cost_per_vulnerability_found.toFixed(4)}<br/>
                  Avg per sample: ${claude_opus.cost_metrics?.avg_cost_per_sample.toFixed(4)}<br/>
                  Tokens: {claude_opus.cost_metrics?.total_tokens_input.toLocaleString()} in / {claude_opus.cost_metrics?.total_tokens_output.toLocaleString()} out
                </div>
              </div>
              <div className="p-4 bg-teal-500/10 rounded-lg">
                <div className="font-semibold text-teal-600">Claude Sonnet 4</div>
                <div className="text-sm text-muted-foreground mt-1">
                  Total: ${claude_sonnet.cost_metrics?.total_cost_usd.toFixed(4)}<br/>
                  Per vulnerability: ${claude_sonnet.cost_metrics?.cost_per_vulnerability_found.toFixed(4)}<br/>
                  Avg per sample: ${claude_sonnet.cost_metrics?.avg_cost_per_sample.toFixed(4)}<br/>
                  Tokens: {claude_sonnet.cost_metrics?.total_tokens_input.toLocaleString()} in / {claude_sonnet.cost_metrics?.total_tokens_output.toLocaleString()} out
                </div>
              </div>
              <div className="p-4 bg-blue-500/10 rounded-lg">
                <div className="font-semibold text-blue-600">SonarQube Enterprise</div>
                <div className="text-sm text-muted-foreground mt-1">
                  Subscription-based pricing (not per-scan)<br/>
                  Enterprise Edition: ~$4,000-$20,000/year<br/>
                  No per-token costs
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </TabsContent>
    </Tabs>
  );
}
