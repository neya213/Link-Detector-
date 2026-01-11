"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Spinner } from "@/components/ui/spinner";
import {
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Search,
  ChevronRight,
  Activity,
} from "lucide-react";
import { toast } from "sonner";
import { ScanResult } from "@/components/types";
import { HighlightedUrl } from "./highlighter";

export function UrlScanner() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) {
      toast.error("Please enter a URL to scan");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch("http://localhost:8000/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ url: url.trim() }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Failed to scan URL");
      }

      const data: ScanResult = await response.json();
      console.log(data);
      setResult(data);
    } catch (err) {
      const message =
        err instanceof Error
          ? err.message
          : "Failed to scan URL. Make sure the backend is running on http://localhost:8000";
      setError(message);
      toast.error("Scan failed", { description: message });
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case "safe":
        return "text-accent";
      case "low":
        return "text-yellow-500";
      case "medium":
        return "text-orange-500";
      case "high":
        return "text-destructive";
      default:
        return "text-muted-foreground";
    }
  };

  const getRiskIcon = (level: string) => {
    switch (level) {
      case "safe":
        return <CheckCircle2 className="h-6 w-6" />;
      case "low":
        return <Shield className="h-6 w-6" />;
      case "medium":
        return <AlertTriangle className="h-6 w-6" />;
      case "high":
        return <XCircle className="h-6 w-6" />;
      default:
        return <Shield className="h-6 w-6" />;
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      {/* Scanner Input */}
      <Card className="border-primary/20 bg-card/50 backdrop-blur">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Search className="h-5 w-5 text-primary" />
            URL Security Scanner
          </CardTitle>
          <CardDescription>
            Enter a URL to analyze using parallel DFA pattern matching
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <Input
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleScan()}
              className="font-mono text-base"
              disabled={loading}
            />
            <Button
              onClick={handleScan}
              disabled={loading}
              size="lg"
              className="min-w-[120px]"
            >
              {loading ? (
                <>
                  <Spinner className="h-4 w-4 mr-2" />
                  Scanning
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  Scan URL
                </>
              )}
            </Button>
          </div>

          {error && (
            <Alert variant="destructive" className="mt-4">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <>
          {/* Risk Overview */}
          <Card
            className={`border-2 ${result.risk_score > 0 ? "border-destructive/50 bg-destructive/5" : "border-accent/50 bg-accent/5"}`}
          >
            <CardContent>
              <div className="flex items-start gap-4">
                <div className={`${getRiskColor(result.risk_level)} mt-1`}>
                  {getRiskIcon(result.risk_level)}
                </div>
                <div className="flex-1 space-y-2">
                  <div className="flex items-center justify-between">
                    <h3 className="text-2xl font-bold">
                      {result.risk_score > 0
                        ? "Suspicious URL Detected"
                        : "URL Appears Safe"}
                    </h3>
                    <Badge
                      variant={
                        result.risk_score > 0 ? "destructive" : "default"
                      }
                      className="text-sm px-3 py-1"
                    >
                      {result.risk_level.toUpperCase()} RISK
                    </Badge>
                  </div>
                  <p className="text-muted-foreground font-mono text-sm break-all">
                    {/* DO THE COLORING HERE. */}
                    <HighlightedUrl result={result}></HighlightedUrl>
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detection Flags */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Detection Results</CardTitle>
              <CardDescription>Parallel DFA execution results</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
                <DetectionFlag
                  label="Suspicious Keywords"
                  active={result.suspicious_flags.has_suspicious_keywords}
                  matches={Object.entries(result.payload.keywords.keywords).map(
                    ([word, count]) => {
                      return `${word} x${count}`;
                    },
                  )}
                />
                <DetectionFlag
                  label="Symbol Abuse"
                  active={result.suspicious_flags.has_symbol_abuse}
                  matches={Object.entries(result.payload.symbols.symbols).map(
                    ([word, count]) => {
                      return `${word} x${count}`;
                    },
                  )}
                />
                <DetectionFlag
                  label="IP Address"
                  active={result.suspicious_flags.has_ip_address}
                  matches={
                    result.payload.ip.ip ? [result.payload.ip.ip] : undefined
                  }
                />
                <DetectionFlag
                  label="Suspicious TLD"
                  active={result.suspicious_flags.has_suspicious_tld}
                  matches={result.payload.domain.matched_subdomains}
                />

                <div className="p-4 rounded-lg border gap-2 col-span-2">
                  <span className="font-medium text-sm">
                    Encoded Characters
                  </span>
                  <div className="my-2"></div>
                  <div className="flex flex-row w-full gap-3">
                    <DetectionFlag
                      label="High Risk"
                      active={result.suspicious_flags.has_encoded_chars}
                      matches={result.payload.encoded.high_risk}
                    />
                    <DetectionFlag
                      label="Low Risk"
                      active={result.suspicious_flags.has_encoded_chars}
                      matches={result.payload.encoded.low_risk}
                    />
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}
    </div>
  );
}

function DetectionFlag({
  label,
  active,
  matches,
}: {
  label: string;
  active: boolean;
  matches?: string[];
}) {
  return (
    <div
      className={`flex-1 p-4 rounded-lg border ${active ? "border-destructive/50 bg-destructive/5" : "border-border bg-card/30"}`}
    >
      <div className="flex items-center gap-2 mb-1">
        {active ? (
          <XCircle className="h-4 w-4 text-destructive" />
        ) : (
          <CheckCircle2 className="h-4 w-4 text-muted-foreground" />
        )}
        <span className="font-medium text-sm">{label}</span>
      </div>
      {matches && matches.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1">
          {matches.map((match, i) => (
            <Badge key={i} variant="destructive" className="text-xs font-mono">
              {match}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

{
  /*
function DFACard({ dfa }: { dfa: DFAAnalysis }) {
  return (
    <div className="p-4 rounded-lg border border-border bg-background/50">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h4 className="font-semibold font-mono text-sm">{dfa.dfa_name}</h4>
          <p className="text-xs text-muted-foreground mt-1">
            Final State:{" "}
            <span className="font-mono text-foreground">{dfa.final_state}</span>
          </p>
        </div>
        <Badge variant={dfa.result ? "destructive" : "secondary"}>
          {dfa.result ? "MATCH" : "NO MATCH"}
        </Badge>
      </div>

      {dfa.matched_pattern && (
        <div className="mb-3 p-2 rounded bg-destructive/10 border border-destructive/20">
          <p className="text-xs text-muted-foreground">Pattern Matched:</p>
          <p className="font-mono text-sm text-destructive">
            {dfa.matched_pattern}
          </p>
        </div>
      )}

      <div>
        <p className="text-xs text-muted-foreground mb-2">State Transitions:</p>
        <div className="flex flex-wrap items-center gap-1">
          {dfa.states_visited.map((state, index) => (
            <div key={index} className="flex items-center">
              <span className="px-2 py-1 rounded bg-primary/10 border border-primary/20 text-xs font-mono text-primary">
                {state}
              </span>
              {index < dfa.states_visited.length - 1 && (
                <ChevronRight className="h-3 w-3 text-muted-foreground mx-1" />
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
*/
}
