import { useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { MetricsOverview } from '@/components/MetricsOverview';
import { ComparisonCharts } from '@/components/ComparisonCharts';
import { DetailedTable } from '@/components/DetailedTable';
import { PerLanguageAnalysis } from '@/components/PerLanguageAnalysis';
import { ResearchContext } from '@/components/ResearchContext';
import { reportData } from '@/data/reportData';
import { 
  Shield, Brain, BarChart3, Table, Globe, 
  FileText, Zap 
} from 'lucide-react';

function Header() {
  return (
    <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-16 items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-blue-500" />
            <span className="text-xl font-bold tracking-tight">SAST<span className="text-blue-500">Compare</span></span>
          </div>
          <Badge variant="outline" className="text-xs">PoC v1.0</Badge>
        </div>
        <div className="flex items-center gap-4 text-sm text-muted-foreground">
          <div className="flex items-center gap-1">
            <Brain className="h-4 w-4 text-red-500" />
            <span>Claude Opus 4.1</span>
          </div>
          <div className="flex items-center gap-1">
            <Zap className="h-4 w-4 text-teal-500" />
            <span>Claude Sonnet 4</span>
          </div>
          <div className="flex items-center gap-1">
            <Shield className="h-4 w-4 text-blue-500" />
            <span>SonarQube Enterprise</span>
          </div>
        </div>
      </div>
    </header>
  );
}

function HeroSection() {
  const { metadata } = reportData;
  const ds = metadata.dataset_stats;
  
  return (
    <div className="relative overflow-hidden rounded-xl bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white p-8">
      <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmZmZmYiIGZpbGwtb3BhY2l0eT0iMC4wMyI+PHBhdGggZD0iTTM2IDM0aDR2NGgtNHpNMjAgMjBoNHY0aC00eiIvPjwvZz48L2c+PC9zdmc+')] opacity-20" />
      <div className="relative z-10">
        <div className="flex items-center gap-2 mb-4">
          <Badge className="bg-blue-500/20 text-blue-300 border-blue-500/30">Enterprise PoC</Badge>
          <Badge className="bg-purple-500/20 text-purple-300 border-purple-500/30">LLM Security Analysis</Badge>
        </div>
        <h1 className="text-3xl md:text-4xl font-bold mb-3">
          LLM vs SonarQube: <span className="text-blue-400">SAST Capability Comparison</span>
        </h1>
        <p className="text-slate-300 max-w-3xl text-base leading-relaxed mb-6">
          Evaluating Claude LLM models against enterprise SonarQube for static application security testing. 
          This PoC analyzes {ds.total_samples} vulnerability samples across {Object.keys(ds.language_distribution).length} languages, 
          measuring detection accuracy, coverage, and cost-effectiveness.
        </p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white/5 backdrop-blur rounded-lg p-3 border border-white/10">
            <div className="text-2xl font-bold text-blue-400">{ds.total_samples}</div>
            <div className="text-xs text-slate-400">Total Samples</div>
          </div>
          <div className="bg-white/5 backdrop-blur rounded-lg p-3 border border-white/10">
            <div className="text-2xl font-bold text-red-400">{ds.vulnerable_count}</div>
            <div className="text-xs text-slate-400">Vulnerable</div>
          </div>
          <div className="bg-white/5 backdrop-blur rounded-lg p-3 border border-white/10">
            <div className="text-2xl font-bold text-green-400">{ds.safe_count}</div>
            <div className="text-xs text-slate-400">Safe Samples</div>
          </div>
          <div className="bg-white/5 backdrop-blur rounded-lg p-3 border border-white/10">
            <div className="text-2xl font-bold text-purple-400">{Object.keys(ds.cwe_distribution).length}</div>
            <div className="text-xs text-slate-400">CWE Categories</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function Footer() {
  return (
    <footer className="border-t py-6 mt-8">
      <div className="container flex flex-col md:flex-row justify-between items-center gap-4 text-sm text-muted-foreground">
        <div>
          LLM vs SonarQube SAST Comparison — PoC Prototype
        </div>
        <div className="flex gap-4">
          <span>Based on research by Szandala et al. (2025), Anthropic (2026)</span>
        </div>
      </div>
    </footer>
  );
}

export default function App() {
  const [activeTab, setActiveTab] = useState('overview');

  return (
    <div className="min-h-screen bg-background">
      <Header />
      
      <main className="container py-6 space-y-6">
        <HeroSection />
        
        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5 h-12">
            <TabsTrigger value="overview" className="gap-1">
              <BarChart3 className="h-4 w-4" />
              Overview
            </TabsTrigger>
            <TabsTrigger value="charts" className="gap-1">
              <Globe className="h-4 w-4" />
              Charts
            </TabsTrigger>
            <TabsTrigger value="details" className="gap-1">
              <Table className="h-4 w-4" />
              Details
            </TabsTrigger>
            <TabsTrigger value="languages" className="gap-1">
              <Shield className="h-4 w-4" />
              Per-Language
            </TabsTrigger>
            <TabsTrigger value="research" className="gap-1">
              <FileText className="h-4 w-4" />
              Research
            </TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4 mt-4">
            <MetricsOverview />
            <DetailedTable />
          </TabsContent>

          <TabsContent value="charts" className="space-y-4 mt-4">
            <ComparisonCharts />
          </TabsContent>

          <TabsContent value="details" className="space-y-4 mt-4">
            <DetailedTable />
            <Card>
              <CardHeader>
                <CardTitle>Confusion Matrices</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {[
                    { name: 'SonarQube', data: reportData.sonarqube.overall_metrics, color: 'blue' },
                    { name: 'Claude Opus 4.1', data: reportData.claude_opus.overall_metrics, color: 'red' },
                    { name: 'Claude Sonnet 4', data: reportData.claude_sonnet.overall_metrics, color: 'teal' },
                  ].map((scanner) => (
                    <div key={scanner.name} className="border rounded-lg p-4">
                      <h4 className={`font-semibold mb-3 text-${scanner.color}-600`}>{scanner.name}</h4>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div className="bg-green-50 border border-green-200 rounded p-2 text-center">
                          <div className="text-lg font-bold text-green-700">{scanner.data.true_positives}</div>
                          <div className="text-xs text-green-600">True Positives</div>
                        </div>
                        <div className="bg-red-50 border border-red-200 rounded p-2 text-center">
                          <div className="text-lg font-bold text-red-700">{scanner.data.false_positives}</div>
                          <div className="text-xs text-red-600">False Positives</div>
                        </div>
                        <div className="bg-amber-50 border border-amber-200 rounded p-2 text-center">
                          <div className="text-lg font-bold text-amber-700">{scanner.data.false_negatives}</div>
                          <div className="text-xs text-amber-600">False Negatives</div>
                        </div>
                        <div className="bg-blue-50 border border-blue-200 rounded p-2 text-center">
                          <div className="text-lg font-bold text-blue-700">{scanner.data.true_negatives}</div>
                          <div className="text-xs text-blue-600">True Negatives</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="languages" className="space-y-4 mt-4">
            <PerLanguageAnalysis />
          </TabsContent>

          <TabsContent value="research" className="space-y-4 mt-4">
            <ResearchContext />
          </TabsContent>
        </Tabs>
      </main>

      <Footer />
    </div>
  );
}
