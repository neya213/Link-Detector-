export interface EncodedDfaResult {
  is_risky: boolean;
  low_risk: string[];
  high_risk: string[];
}
export interface IPDfaResult {
  ip: string | undefined;
  risk_score: number;
}
export interface KeywordDfaResult {
  risk_score: number;
  keywords: Record<string, number>;
}
export interface SymbolsDfaResult {
  risk_score: number;
  symbols: Record<string, number>;
}
export interface DomainDfaResult {
  risk_score: number;
  matched_subdomains: string[];
}

export interface Payload {
  keywords: KeywordDfaResult;
  symbols: SymbolsDfaResult;
  ip: IPDfaResult;
  domain: DomainDfaResult;
  encoded: EncodedDfaResult;
}

export interface ScanResult {
  url: string;
  risk_score: number;
  risk_level: "safe" | "low" | "medium" | "high";
  suspicious_flags: {
    has_suspicious_keywords: boolean;
    has_symbol_abuse: boolean;
    has_ip_address: boolean;
    has_suspicious_tld: boolean;
    has_encoded_chars: boolean;
  };
  redirects: {
    has_redirects: string;
    previous_url: string;
    final_url: string;
  };
  payload: Payload;
}
