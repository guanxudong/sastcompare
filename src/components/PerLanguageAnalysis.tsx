import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { reportData } from '@/data/reportData';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer
} from 'recharts';

export function PerLanguageAnalysis() {
  const { sonarqube, claude_opus, claude_sonnet } = reportData;

  // Build per-language comparison data
  const languages = Object.keys(sonarqube.language_metrics);
  
  const langComparisonData = languages.map((lang) => ({
    language: lang,
    'SonarQube F1': sonarqube.language_metrics[lang]?.f1_score || 0,
    'Claude Opus F1': claude_opus.language_metrics[lang]?.f1_score || 0,
    'Claude Sonnet F1': claude_sonnet.language_metrics[lang]?.f1_score || 0,
    'SonarQube Recall': sonarqube.language_metrics[lang]?.recall || 0,
    'Claude Opus Recall': claude_opus.language_metrics[lang]?.recall || 0,
    'Claude Sonnet Recall': claude_sonnet.language_metrics[lang]?.recall || 0,
  }));

  const vulnTypeData = Object.keys(sonarqube.vuln_type_metrics).map((vt) => ({
    type: vt,
    'SonarQube': sonarqube.vuln_type_metrics[vt]?.recall || 0,
    'Claude Opus': claude_opus.vuln_type_metrics[vt]?.recall || 0,
    'Claude Sonnet': claude_sonnet.vuln_type_metrics[vt]?.recall || 0,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Per-Language F1 Score</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={langComparisonData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="language" />
              <YAxis domain={[0, 1]} />
              <Tooltip />
              <Legend />
              <Bar dataKey="SonarQube F1" fill="#4C9AFF" />
              <Bar dataKey="Claude Opus F1" fill="#FF6B6B" />
              <Bar dataKey="Claude Sonnet F1" fill="#4ECDC4" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Per-Vulnerability-Type Recall</CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={vulnTypeData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" domain={[0, 1]} />
              <YAxis dataKey="type" type="category" width={120} style={{ fontSize: 11 }} />
              <Tooltip />
              <Legend />
              <Bar dataKey="SonarQube" fill="#4C9AFF" />
              <Bar dataKey="Claude Opus" fill="#FF6B6B" />
              <Bar dataKey="Claude Sonnet" fill="#4ECDC4" />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle>Language Detection Breakdown</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {languages.map((lang) => {
              const sq = sonarqube.language_metrics[lang];
              const op = claude_opus.language_metrics[lang];
              const sn = claude_sonnet.language_metrics[lang];
              const totalInLang = (sq?.true_positives || 0) + (sq?.false_positives || 0) + 
                                  (sq?.true_negatives || 0) + (sq?.false_negatives || 0);
              return (
                <div key={lang} className="p-4 border rounded-lg">
                  <h4 className="font-semibold mb-2">{lang}</h4>
                  <div className="text-sm space-y-1">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Samples:</span>
                      <span>{totalInLang}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-blue-500">SonarQube F1:</span>
                      <span className="font-mono">{sq?.f1_score.toFixed(4)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-red-500">Opus F1:</span>
                      <span className="font-mono">{op?.f1_score.toFixed(4)}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-teal-500">Sonnet F1:</span>
                      <span className="font-mono">{sn?.f1_score.toFixed(4)}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
