import { ScanResult } from "@/components/types";

type HighlightingType =
  | "keyword"
  | "symbol"
  | "subdomain"
  | "ip"
  | "low_risk"
  | "high_risk";

const HIGHLIGHT_STYLES = {
  keyword: "bg-yellow-300/40 text-white",
  symbol: "bg-purple-300/40 text-white",
  subdomain: "bg-blue-300/40 text-white",
  ip: "bg-red-400/40 text-white",
  low_risk: "bg-green-300/40 text-black",
  high_risk: "bg-red-500/40 text-white",
} satisfies Record<HighlightingType, string>;

function extractTokens(
  result: ScanResult,
): { value: string; type: HighlightingType }[] {
  const tokens: { value: string; type: HighlightingType }[] = [];

  // Keywords
  for (const k of Object.keys(result.payload.keywords.keywords)) {
    tokens.push({ value: k, type: "keyword" });
  }

  // Symbols
  for (const s of Object.keys(result.payload.symbols.symbols)) {
    tokens.push({ value: s, type: "symbol" });
  }

  // Subdomains
  for (const sub of result.payload.domain.matched_subdomains) {
    tokens.push({ value: sub, type: "subdomain" });
  }

  // IP
  if (result.payload.ip.ip) {
    tokens.push({ value: result.payload.ip.ip, type: "ip" });
  }

  // Encoded
  for (const w of result.payload.encoded.low_risk) {
    tokens.push({ value: w, type: "low_risk" });
  }

  for (const w of result.payload.encoded.high_risk) {
    tokens.push({ value: w, type: "high_risk" });
  }

  return tokens;
}

function highlightUrl(
  url: string,
  tokens: { value: string; type: HighlightingType }[],
): React.ReactNode[] {
  if (!tokens.length) return [url];

  // Sort longest first to avoid partial overlaps
  const sorted = [...tokens].sort((a, b) => b.value.length - a.value.length);

  const regex = new RegExp(
    `(${sorted.map((t) => escapeRegex(t.value)).join("|")})`,
    "gi",
  );

  return url.split(regex).map((part, i) => {
    const token = sorted.find(
      (t) => t.value.toLowerCase() === part.toLowerCase(),
    );

    if (!token) return part;

    return (
      <span key={i} className={`px-1 rounded ${HIGHLIGHT_STYLES[token.type]}`}>
        {part}
      </span>
    );
  });
}
function escapeRegex(str: string) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

type Props = {
  result: ScanResult;
};

export function HighlightedUrl({ result: url_input }: Props) {
  const tokens = extractTokens(url_input);
  const highlighted = highlightUrl(url_input.url, tokens);

  return (
    <div className="font-mono break-all text-sm text-white/80">
      {highlighted}
    </div>
  );
}
