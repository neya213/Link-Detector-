import { UrlScanner } from "@/components/url-scanner"
import { Shield, Cpu, Activity } from "lucide-react"

export default function Home() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border/40">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="h-8 w-8 text-primary" />
              <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">PhishGuard</h1>
              <p className="text-xs text-muted-foreground">DFA Security Scanner</p>
            </div>
          </div>
          <div className="flex items-center gap-6 text-sm text-muted-foreground">
            <a href="#how-it-works" className="hover:text-foreground transition-colors">
              How It Works
            </a>
            <a href="#about" className="hover:text-foreground transition-colors">
              About DFA
            </a>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 pt-20 pb-16">
        <div className="max-w-3xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-primary/10 border border-primary/20 text-primary text-sm">
            <Cpu className="h-4 w-4" />
            <span className="font-mono">Automata Theory Project</span>
          </div>
          <h2 className="text-5xl md:text-6xl font-bold tracking-tight text-balance">
            Advanced Phishing Detection Using <span className="text-primary">Finite Automata</span>
          </h2>
          <p className="text-xl text-muted-foreground text-balance leading-relaxed">
            Analyze URLs in real-time using parallel Deterministic Finite Automata. See state transitions, pattern
            matching, and security analysis in action.
          </p>
        </div>
      </section>

      {/* Scanner Component */}
      <section className="container mx-auto px-4 pb-20">
        <UrlScanner />
      </section>

      {/* Features */}
      <section id="how-it-works" className="border-t border-border/40 bg-card/30">
        <div className="container mx-auto px-4 py-20">
          <div className="max-w-5xl mx-auto">
            <h3 className="text-3xl font-bold mb-12 text-center">How It Works</h3>
            <div className="grid md:grid-cols-3 gap-8">
              <div className="space-y-3">
                <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Activity className="h-6 w-6 text-primary" />
                </div>
                <h4 className="text-lg font-semibold">Keyword DFA</h4>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Scans for suspicious terms like "verify", "urgent", "suspended" commonly used in phishing attacks.
                </p>
              </div>
              <div className="space-y-3">
                <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Activity className="h-6 w-6 text-primary" />
                </div>
                <h4 className="text-lg font-semibold">Symbol Analysis DFA</h4>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Detects unusual patterns like excessive dots, dashes, or domain obfuscation techniques.
                </p>
              </div>
              <div className="space-y-3">
                <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Activity className="h-6 w-6 text-primary" />
                </div>
                <h4 className="text-lg font-semibold">TLD & IP Detection</h4>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Identifies suspicious top-level domains and raw IP addresses used to bypass domain tracking.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/40">
        <div className="container mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm text-muted-foreground">
            <p>Built with FastAPI + Next.js for Automata Theory</p>
            <p>Demonstrating DFA state machines in cybersecurity</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
