
## UNUSED CODE HERE ##
from enum import Enum
from typing import Callable

SUSPICIOUS_DOMAIN_TOKENS = [
    "xyz", "top", "click", "link", "live", "online", "site",
    "info", "zip", "tk", "ml", "ga", "cf", "gq", "icu",
    "support", "review", "country", "stream", "loan",
    "money", "account", "bank", "app", "cloud", "service"
]

class State(str, Enum):
    START = "START"
    SCHEME = "SCHEME"
    DOMAIN = "DOMAIN"
    END_DOMAIN = "END_DOMAIN"
    REJECT = "REJECT"

TransitionHook = Callable[[State, str, State], None]

def _noop_transition(_: State, _2: str, _3: State) -> None:
    pass


class DFATracer:
    path: list[dict[str, object]]

    def __init__(self):
        self.path = []

    def on_transition(self, from_state: State, symbol: str, to_state: State):
        self.path.append({
            "from": from_state,
            "symbol": symbol,
            "to": to_state
        })

class DomainDFA:
    on_transition: TransitionHook

    def __init__(self, on_transition: TransitionHook | None = None):
        self.on_transition = on_transition or _noop_transition

    def _emit(self, from_state: State, symbol: str, to_state: State):
        self.on_transition(from_state, symbol, to_state)

    def run(self, text: str) -> tuple[State, str]:
        text = text.lower().strip()
        state = State.START
        domain = ""

        i = 0
        while i < len(text):
            c = text[i]

            if state == State.START:
                if text[i:i+3] == "://":
                    i += 3
                    continue
                if c.isalpha():
                    i += 1
                    continue
                if c.isalnum():
                    self._emit(state, c, State.DOMAIN)
                    state = State.DOMAIN
                    domain += c
                    i += 1
                    continue

                self._emit(state, c, State.DOMAIN)
                state = State.DOMAIN

            elif state == State.DOMAIN:
                if c in "/:":
                    self._emit(state, c, State.END_DOMAIN)
                    state = State.END_DOMAIN
                    break

                self._emit(state, c, State.DOMAIN)
                domain += c

            i += 1

        if not domain or "." not in domain:
            self._emit(state, "∅", State.REJECT)
            return State.REJECT, ""

        return state, domain

class DomainSubstringChecker:
    def check(self, domain: str):
        hits = [
            token for token in SUSPICIOUS_DOMAIN_TOKENS
            if token in domain
        ]

        return {
            "hits": hits,
            "suspicious": bool(hits)
        }

def dfa_analyze(url: str):
    tracer = DFATracer()
    dfa = DomainDFA(on_transition=tracer.on_transition)

    final_state, domain = dfa.run(url)

    if final_state == State.REJECT:
        return {
            "verdict": False,
            "trace": tracer.path
        }

    policy = DomainSubstringChecker().check(domain)

    return {
        "verdict": policy["suspicious"],
        "domain": domain,
        "tld": policy["tld"],
        "trace": tracer.path
    }

## UNUSED CODE ABOVE ##

def dfa_tld(text: str):
    text = text.lower().strip()

    if "://" in text:
        domain = text.split("://", 1)[1].split("/")[0]
    else:
        domain = text.split("/")[0]

    domain = domain.split(":")[0]

    if "." not in domain:
        return False

    tld = domain.split(".")[-1]
    return tld in SUSPICIOUS_DOMAIN_TOKENS
