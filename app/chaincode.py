"""
PurposePay - cross-border CBDC smart-contract simulation (hackathon PoC).

What this module simulates (and what production replaces it with):

  * Two-tier ledger     -> hash-chained in-memory blocks   (Hyperledger Fabric / Corda)
  * HSM signing         -> SHA-256 stand-in                (FIPS 140-2 Level 3 HSM)
  * ZKP cap check       -> hash-commitment stand-in        (on-chain zero-knowledge range proof)
  * FX oracle           -> static rate table               (Bloomberg / Refinitiv feeds)
  * Merchant registry   -> in-memory MCC + terminal table  (NPCI UPI / e-rupee QR parsing)

All figures are illustrative. Nothing here is measured production performance.
"""
from __future__ import annotations

import hashlib
import json
import math
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------- #
# Policy configuration (regulator-controlled parameters in production)
# --------------------------------------------------------------------------- #

# LRS limit is USD 250,000 per financial year for resident individuals sending
# money out of India. For inward NRI corridors the same proof circuit enforces
# whatever corridor / AML cap the regulator sets, so the cap is a policy value.
ANNUAL_CAP_USD = 250_000.0
FX_LOCK_SECONDS = 30

FX_RATES: Dict[str, Dict[str, Any]] = {
    "USD": {"rate": 83.50, "bank": "Citi New York node", "country": "USA"},
    "AED": {"rate": 22.85, "bank": "Emirates NBD Â· CBUAE node", "country": "UAE"},
    "HKD": {"rate": 10.72, "bank": "HSBC Hong Kong node", "country": "Hong Kong"},
    "SGD": {"rate": 62.40, "bank": "DBS Singapore node", "country": "Singapore"},
}

INITIAL_BALANCES: Dict[str, float] = {
    "USD": 300_000.00,
    "AED": 1_100_000.00,
    "HKD": 2_300_000.00,
    "SGD": 400_000.00,
}

# Purpose buckets -> allowed Merchant Category Codes and designated terminals.
BUCKET_RULES: Dict[str, Dict[str, Any]] = {
    "EDUCATION": {
        "label": "Education",
        "mccs": {8211: "Schools", 8220: "Colleges & universities", 8299: "Other educational services"},
        "terminals": ["BILLING"],
        "prohibited": {},
    },
    "HEALTHCARE": {
        "label": "Healthcare",
        "mccs": {
            8062: "Hospitals",
            8011: "Doctors",
            8021: "Dentists",
            8099: "Medical services",
            5912: "Pharmacies",
        },
        "terminals": ["BILLING", "PHARMACY"],
        "prohibited": {},
    },
    "GENERAL": {
        "label": "General",
        "mccs": None,  # any MCC that is not prohibited
        "terminals": None,
        "prohibited": {5921: "Liquor stores", 7995: "Gambling"},
    },
}

# Simulated merchant registry as an acquirer would hold it: MCC + terminal class.
MERCHANTS: Dict[str, Dict[str, Any]] = {
    "MERCHANT_APOLLO_HOSPITAL": {
        "name": "Apollo Hospital", "mcc": 8062, "terminal": "BILLING",
        "mcc_label": "Hospitals", "icon": "ðŸ¥",
    },
    "MERCHANT_APOLLO_PHARMACY": {
        "name": "Apollo Pharmacy", "mcc": 5912, "terminal": "PHARMACY",
        "mcc_label": "Pharmacies", "icon": "ðŸ’Š",
    },
    "MERCHANT_HOSPITAL_CAFETERIA": {
        "name": "Hospital Cafeteria", "mcc": 8062, "terminal": "CAFETERIA",
        "mcc_label": "Hospitals (parent MCC)", "icon": "ðŸ½ï¸",
    },
    "MERCHANT_DPS_SCHOOL": {
        "name": "DPS School", "mcc": 8211, "terminal": "BILLING",
        "mcc_label": "Schools", "icon": "ðŸŽ“",
    },
    "MERCHANT_GENERAL_STORE": {
        "name": "City Supermarket", "mcc": 5411, "terminal": "RETAIL",
        "mcc_label": "Grocery stores", "icon": "ðŸ›’",
    },
    "MERCHANT_ELECTRONICS": {
        "name": "Electronics Mart", "mcc": 5732, "terminal": "RETAIL",
        "mcc_label": "Electronics stores", "icon": "ðŸ’»",
    },
    "MERCHANT_LIQUOR_STORE": {
        "name": "Wine & Spirits", "mcc": 5921, "terminal": "RETAIL",
        "mcc_label": "Liquor stores", "icon": "ðŸ·",
    },
}

BUCKET_KEYS = ("education", "healthcare", "general")


def _r2(value: float) -> float:
    return round(float(value) + 0.0, 2)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class CBDCSmartContract:
    def __init__(self) -> None:
        self.reset()

    # ------------------------------------------------------------------ #
    # State
    # ------------------------------------------------------------------ #
    def reset(self) -> Dict[str, Any]:
        """Return the simulation to a clean state (handy between demo runs)."""
        self.fx_rates: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in FX_RATES.items()}
        self.sender_balances: Dict[str, float] = dict(INITIAL_BALANCES)
        self.receiver_wallet: Dict[str, float] = {"education": 0.0, "healthcare": 0.0, "general": 0.0, "total": 0.0}
        self.merchants: Dict[str, Dict[str, Any]] = {k: dict(v) for k, v in MERCHANTS.items()}
        self.cap_usd: float = ANNUAL_CAP_USD
        self.used_usd: float = 0.0
        self.ledger: List[Dict[str, Any]] = []
        self.payments: List[Dict[str, Any]] = []
        self.tier1_issued_inr: float = 0.0
        self.tier2_spent_inr: float = 0.0
        self._seq: int = 0
        self.last_transfer: Optional[Dict[str, Any]] = None
        self._append_block("GENESIS", "Tier 1", "RBI issuer node online. Purpose-bound policy loaded.")
        return self.get_state()

    def rules_public(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        for key, rule in BUCKET_RULES.items():
            out[key] = {
                "label": rule["label"],
                "mccs": [{"mcc": m, "name": n} for m, n in (rule["mccs"] or {}).items()],
                "any_mcc": rule["mccs"] is None,
                "terminals": rule["terminals"] or [],
                "prohibited": [{"mcc": m, "name": n} for m, n in rule["prohibited"].items()],
            }
        return out

    def get_state(self) -> Dict[str, Any]:
        """Current ledger, oracle rates, wallet balances and policy parameters."""
        usd_rate = self.fx_rates["USD"]["rate"]
        return {
            "fx_rates": self.fx_rates,
            "sender_balances": self.sender_balances,
            "receiver_inr": self.receiver_wallet,
            "merchants": [dict(v, id=k) for k, v in self.merchants.items()],
            "rules": self.rules_public(),
            "cap": {
                "limit_usd": self.cap_usd,
                "used_usd": _r2(self.used_usd),
                "remaining_usd": _r2(self.cap_usd - self.used_usd),
            },
            # Legacy keys (INR) kept for older clients
            "lrs_limit": _r2(self.cap_usd * usd_rate),
            "lrs_used": _r2(self.used_usd * usd_rate),
            "tiers": {
                "tier1_issued_inr": _r2(self.tier1_issued_inr),
                "tier2_spent_inr": _r2(self.tier2_spent_inr),
                "tier2_outstanding_inr": _r2(self.tier1_issued_inr - self.tier2_spent_inr),
            },
            "ledger": self.ledger[-14:][::-1],
            "ledger_height": len(self.ledger),
            "payments": self.payments[-8:][::-1],
            "last_transfer": self.last_transfer,
            "fx_lock_seconds": FX_LOCK_SECONDS,
        }

    # ------------------------------------------------------------------ #
    # Ledger helpers
    # ------------------------------------------------------------------ #
    def _append_block(self, kind: str, tier: str, summary: str) -> Dict[str, Any]:
        prev = self.ledger[-1]["hash"] if self.ledger else "0" * 64
        height = len(self.ledger)
        body = json.dumps({"h": height, "k": kind, "t": tier, "s": summary, "p": prev}, sort_keys=True)
        block = {
            "height": height,
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "kind": kind,
            "tier": tier,
            "summary": summary,
            "prev": prev,
            "hash": _sha(body),
        }
        self.ledger.append(block)
        return block

    def _next_e2e(self) -> str:
        self._seq += 1
        return f"PURPOSEPAY-{datetime.now(timezone.utc).year}-{self._seq:05d}"

    # ------------------------------------------------------------------ #
    # Compliance simulation
    # ------------------------------------------------------------------ #
    def _cap_proof(self, amount_usd: float) -> Dict[str, Any]:
        """
        Stand-in for a zero-knowledge range proof of: committed_total + amount <= cap.
        The commitment hides the running total; only the verdict is meant to be public.
        """
        commitment = _sha(f"total:{self.used_usd:.2f}:salt:{self._seq}")
        within = (self.used_usd + amount_usd) <= self.cap_usd + 1e-9
        proof = _sha(f"{commitment}:{amount_usd:.2f}:{self.cap_usd:.0f}:{within}")
        return {
            "scheme": "Simulated range proof (hash commitment)",
            "statement": "committed_total + amount <= annual_cap",
            "commitment": commitment[:24],
            "proof": proof[:32],
            "verified": within,
            "public_output": "WITHIN_CAP" if within else "CAP_EXCEEDED",
            "reveals": "Verdict only. No balance or history is published.",
        }

    @staticmethod
    def _sanctions_screen(country: str) -> Dict[str, Any]:
        return {
            "lists": ["OFAC SDN", "FIU-IND"],
            "parties": [f"NRI Sender ({country})", "Receiver Family (India)"],
            "result": "CLEAR",
        }

    # ------------------------------------------------------------------ #
    # ISO 20022 message builders
    # ------------------------------------------------------------------ #
    @staticmethod
    def _pacs008(e2e: str, currency: str, amount: float, country: str, edu: float, health: float, gen: float) -> str:
        return (
            '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.008.001.10">\n'
            "  <CdtTrfTxInf>\n"
            f"    <PmtId><EndToEndId>{e2e}</EndToEndId></PmtId>\n"
            f'    <IntrBkSttlmAmt Ccy="{currency}">{amount:.2f}</IntrBkSttlmAmt>\n'
            f"    <Dbtr><Nm>NRI Sender ({country})</Nm></Dbtr>\n"
            "    <Cdtr><Nm>Receiver Family (India)</Nm></Cdtr>\n"
            "    <SplmtryData>\n"
            "      <Envlp>\n"
            "        <PurposeAllocation>\n"
            f"          <EducationPct>{edu:.1f}</EducationPct>\n"
            f"          <HealthcarePct>{health:.1f}</HealthcarePct>\n"
            f"          <GeneralPct>{gen:.1f}</GeneralPct>\n"
            "        </PurposeAllocation>\n"
            "      </Envlp>\n"
            "    </SplmtryData>\n"
            "  </CdtTrfTxInf>\n"
            "</Document>"
        )

    @staticmethod
    def _pacs002(e2e: str, status: str) -> str:
        note = {
            "ACCC": "AcceptedSettlementCompleted",
            "RJCT": "Rejected",
        }.get(status, status)
        return (
            '<Document xmlns="urn:iso:std:iso:20022:tech:xsd:pacs.002.001.12">\n'
            "  <TxInfAndSts>\n"
            f"    <OrgnlEndToEndId>{e2e}</OrgnlEndToEndId>\n"
            f"    <TxSts>{status}</TxSts> <!-- {note} -->\n"
            "  </TxInfAndSts>\n"
            "</Document>"
        )

    # ------------------------------------------------------------------ #
    # SWIFT vs PurposePay comparison (modelled, not measured)
    # ------------------------------------------------------------------ #
    def calculate_comparison(
        self,
        currency: str,
        amount: float,
        edu_pct: float = 40.0,
        health_pct: float = 40.0,
        gen_pct: float = 20.0,
    ) -> Dict[str, Any]:
        currency = str(currency).upper().strip()
        amount = float(amount)
        edu_pct, health_pct, gen_pct = float(edu_pct), float(health_pct), float(gen_pct)

        if currency not in self.fx_rates:
            raise ValueError(f"Unsupported currency: {currency}")

        rate = float(self.fx_rates[currency]["rate"])
        gross_inr = amount * rate

        total_pct = edu_pct + health_pct + gen_pct
        if total_pct <= 0:
            edu_pct, health_pct, gen_pct, total_pct = 40.0, 40.0, 20.0, 100.0

        # Modelled SWIFT costs (assumptions, labelled as such in the UI)
        wire_fee_inr = max(gross_inr * 0.01, 500.0) if gross_inr > 0 else 0.0
        fx_markup_inr = gross_inr * 0.025
        intermediary_fees_inr = min(gross_inr * 0.015, 3000.0) if gross_inr > 0 else 0.0
        total_swift_fees = wire_fee_inr + fx_markup_inr + intermediary_fees_inr
        swift_net_inr = max(0.0, gross_inr - total_swift_fees)

        def split(net: float) -> Dict[str, float]:
            return {
                "education_inr": net * (edu_pct / total_pct),
                "healthcare_inr": net * (health_pct / total_pct),
                "general_inr": net * (gen_pct / total_pct),
            }

        cbdc_net_inr = gross_inr  # intermediary fees modelled as INR 0 in the PoC
        savings_inr = cbdc_net_inr - swift_net_inr
        savings_pct = (savings_inr / gross_inr * 100) if gross_inr > 0 else 0.0

        return {
            "currency": currency,
            "amount": amount,
            "fx_rate": rate,
            "gross_inr": gross_inr,
            "fee_pct_of_gross": round((total_swift_fees / gross_inr * 100) if gross_inr > 0 else 0.0, 2),
            "traditional_swift": {
                "wire_fee_inr": wire_fee_inr,
                "fx_markup_inr": fx_markup_inr,
                "intermediary_fees_inr": intermediary_fees_inr,
                "total_fees_inr": total_swift_fees,
                "net_received_inr": swift_net_inr,
                "time_taken": "1â€“3 business days",
                "hops": "2â€“4 correspondent banks",
                "allocations": split(swift_net_inr),
            },
            "purposepay_cbdc": {
                "total_fees_inr": 0.0,
                "net_received_inr": cbdc_net_inr,
                "time_taken": "Under 3 seconds (target)",
                "hops": "Direct two-tier ledger settlement",
                "allocations": split(cbdc_net_inr),
            },
            "savings": {
                "direct_inr": savings_inr,
                "percentage": round(savings_pct, 2),
                "time_saved": "1â€“3 days",
            },
            "model_note": (
                "SWIFT costs are modelled: 1% wire fee (min INR 500), 2.5% FX spread, "
                "1.5% correspondent fees (max INR 3,000). PurposePay intermediary fees are modelled as INR 0."
            ),
        }

    def simulate_traditional_swift(self, currency: str = "USD", amount: float = 1000.0,
                                   edu_pct: float = 40.0, health_pct: float = 40.0,
                                   gen_pct: float = 20.0) -> Dict[str, Any]:
        return self.calculate_comparison(currency, amount, edu_pct, health_pct, gen_pct)

    # ------------------------------------------------------------------ #
    # Cross-border transfer (mint into purpose buckets)
    # ------------------------------------------------------------------ #
    def process_cross_border_transfer(
        self,
        currency: str,
        amount: float,
        edu_pct: float = 40.0,
        health_pct: float = 40.0,
        gen_pct: float = 20.0,
    ) -> Tuple[bool, str, Dict[str, Any]]:
        t_start = time.perf_counter()
        try:
            currency = str(currency).upper().strip()
            amount = float(amount)
            edu_pct, health_pct, gen_pct = float(edu_pct), float(health_pct), float(gen_pct)
        except (TypeError, ValueError):
            return False, "Invalid numeric input.", {"failed_step": "initiate"}

        if not all(math.isfinite(v) for v in (amount, edu_pct, health_pct, gen_pct)):
            return False, "Invalid numeric input.", {"failed_step": "initiate"}
        if currency not in self.fx_rates:
            return False, f"Unsupported currency code: {currency}", {"failed_step": "initiate"}
        if amount <= 0:
            return False, "Transfer amount must be greater than zero.", {"failed_step": "initiate"}
        if min(edu_pct, health_pct, gen_pct) < 0:
            return False, "Allocation percentages cannot be negative.", {"failed_step": "initiate"}
        total_pct = edu_pct + health_pct + gen_pct
        if abs(total_pct - 100.0) > 0.01:
            return False, f"Allocation percentages must total exactly 100%. Current total: {total_pct:g}%", {"failed_step": "initiate"}
        if self.sender_balances.get(currency, 0.0) < amount:
            return False, f"Insufficient {currency} balance in sender node wallet.", {"failed_step": "initiate"}

        country = self.fx_rates[currency]["country"]
        rate = float(self.fx_rates[currency]["rate"])
        usd_rate = float(self.fx_rates["USD"]["rate"])
        e2e = self._next_e2e()
        steps: List[Dict[str, Any]] = []

        # Step 1: initiation (build pacs.008)
        t0 = time.perf_counter()
        pacs008 = self._pacs008(e2e, currency, amount, country, edu_pct, health_pct, gen_pct)
        steps.append({"id": "initiate", "title": "Initiate", "detail": "pacs.008 built",
                      "ms": round((time.perf_counter() - t0) * 1000, 3)})

        # Step 2: compliance (ZKP cap proof + sanctions)
        t0 = time.perf_counter()
        gross_inr = _r2(amount * rate)
        amount_usd = gross_inr / usd_rate
        proof = self._cap_proof(amount_usd)
        sanctions = self._sanctions_screen(country)
        cap_info = {
            "limit_usd": self.cap_usd,
            "used_usd": _r2(self.used_usd),
            "remaining_usd": _r2(self.cap_usd - self.used_usd),
            "this_transfer_usd": _r2(amount_usd),
        }
        if not proof["verified"]:
            pacs002 = self._pacs002(e2e, "RJCT")
            msg = (
                f"Regulatory cap exceeded. Proof failed: this transfer (â‰ˆ ${amount_usd:,.2f}) is above "
                f"the remaining annual limit of ${self.cap_usd - self.used_usd:,.2f}."
            )
            return False, msg, {
                "failed_step": "comply",
                "e2e_id": e2e,
                "compliance": {"zkp": proof, "sanctions": sanctions, "cap": cap_info},
                "iso20022": {"pacs008": pacs008, "pacs002": pacs002},
            }
        steps.append({"id": "comply", "title": "Comply", "detail": "ZKP + sanctions clear",
                      "ms": round((time.perf_counter() - t0) * 1000, 3)})

        # Step 3: HSM signature + FX lock
        t0 = time.perf_counter()
        signature = _sha(f"HSM-SIM-KEY:{pacs008}")[:40]
        fx = {"pair": f"{currency}/INR", "rate": rate, "locked_for_s": FX_LOCK_SECONDS,
              "source": "FX oracle (simulated static rates)"}
        security = {"hsm": "FIPS 140-2 Level 3 HSM (simulated)", "signature": signature}
        steps.append({"id": "fx", "title": "Lock FX", "detail": "signed, rate locked",
                      "ms": round((time.perf_counter() - t0) * 1000, 3)})

        # Step 4: atomic settlement (debit, mint, split)
        t0 = time.perf_counter()
        edu_amt = _r2(gross_inr * edu_pct / 100.0)
        health_amt = _r2(gross_inr * health_pct / 100.0)
        gen_amt = _r2(gross_inr - edu_amt - health_amt)  # remainder keeps the sum exact

        self.sender_balances[currency] = _r2(self.sender_balances[currency] - amount)
        self.receiver_wallet["education"] = _r2(self.receiver_wallet["education"] + edu_amt)
        self.receiver_wallet["healthcare"] = _r2(self.receiver_wallet["healthcare"] + health_amt)
        self.receiver_wallet["general"] = _r2(self.receiver_wallet["general"] + gen_amt)
        self.receiver_wallet["total"] = _r2(self.receiver_wallet["total"] + gross_inr)
        self.used_usd += amount_usd
        self.tier1_issued_inr += gross_inr

        blocks = [
            self._append_block("ISSUE", "Tier 1",
                               f"RBI node issues â‚¹{gross_inr:,.2f} eâ‚¹ against {amount:,.2f} {currency} Â· {e2e}"),
            self._append_block("DISTRIBUTE", "Tier 2",
                               f"Bank node credits wallet: Edu â‚¹{edu_amt:,.0f} Â· Health â‚¹{health_amt:,.0f} Â· Gen â‚¹{gen_amt:,.0f}"),
        ]
        steps.append({"id": "settle", "title": "Settle", "detail": "minted into buckets",
                      "ms": round((time.perf_counter() - t0) * 1000, 3)})

        pacs002 = self._pacs002(e2e, "ACCC")
        comparison = self.calculate_comparison(currency, amount, edu_pct, health_pct, gen_pct)

        message = (
            f"Successfully minted â‚¹{gross_inr:,.2f} e-Rupee from {amount:,.2f} {currency}. "
            f"Allocated: Education â‚¹{edu_amt:,.2f}, Healthcare â‚¹{health_amt:,.2f}, General â‚¹{gen_amt:,.2f}."
        )

        result = {
            "e2e_id": e2e,
            "currency": currency,
            "amount": amount,
            "gross_inr": gross_inr,
            "fx": fx,
            "allocation": {"education": edu_amt, "healthcare": health_amt, "general": gen_amt},
            "split_pct": {"education": edu_pct, "healthcare": health_pct, "general": gen_pct},
            "compliance": {
                "zkp": proof,
                "sanctions": sanctions,
                "cap": {
                    "limit_usd": self.cap_usd,
                    "used_usd": _r2(self.used_usd),
                    "remaining_usd": _r2(self.cap_usd - self.used_usd),
                    "this_transfer_usd": _r2(amount_usd),
                },
            },
            "security": security,
            "iso20022": {"pacs008": pacs008, "pacs002": pacs002},
            "steps": steps,
            "blocks": blocks,
            "engine_ms": round((time.perf_counter() - t_start) * 1000, 3),
            "comparison": comparison,
        }
        self.last_transfer = {
            "e2e_id": e2e, "currency": currency, "amount": amount, "gross_inr": gross_inr,
            "iso20022": result["iso20022"], "security": security, "compliance": result["compliance"],
            "allocation": result["allocation"], "engine_ms": result["engine_ms"],
        }
        return True, message, result

    def transfer(self, currency: str, amount: float, edu_pct: float = 40.0,
                 health_pct: float = 40.0, gen_pct: float = 20.0) -> Tuple[bool, str, Dict[str, Any]]:
        """Alias kept for main.py compatibility."""
        return self.process_cross_border_transfer(currency, amount, edu_pct, health_pct, gen_pct)

    # ------------------------------------------------------------------ #
    # Point-of-sale payment with MCC + terminal enforcement
    # ------------------------------------------------------------------ #
    def pay_merchant(self, merchant_id: str, category: str, amount_inr: float) -> Tuple[bool, str, Dict[str, Any]]:
        merchant_id = str(merchant_id).strip()
        bucket = str(category).strip().upper()
        try:
            amount_inr = float(amount_inr)
        except (TypeError, ValueError):
            return False, "Payment amount must be a number.", {"reason": "INVALID_AMOUNT", "decision": "BLOCKED"}

        if not math.isfinite(amount_inr) or amount_inr <= 0:
            return False, "Payment amount must be greater than 0.", {"reason": "INVALID_AMOUNT", "decision": "BLOCKED"}

        merchant = self.merchants.get(merchant_id)
        if merchant is None:
            return False, f"Unknown merchant '{merchant_id}'.", {"reason": "UNKNOWN_MERCHANT", "decision": "BLOCKED"}
        rule = BUCKET_RULES.get(bucket)
        if rule is None:
            return False, f"Unknown eâ‚¹ bucket '{category}'.", {"reason": "UNKNOWN_BUCKET", "decision": "BLOCKED"}

        mcc = merchant["mcc"]
        terminal = merchant["terminal"]
        details: Dict[str, Any] = {
            "merchant_id": merchant_id,
            "merchant": merchant["name"],
            "mcc": mcc,
            "mcc_label": merchant["mcc_label"],
            "terminal": terminal,
            "bucket": bucket,
            "amount_inr": _r2(amount_inr),
            # The MCC travels in the standard UPI QR payload (parameter "mc").
            "qr_payload": f"upi://pay?pa={merchant_id.lower()}@purposepay&mc={mcc}&tn=PurposePay",
        }

        def block(reason: str, text: str) -> Tuple[bool, str, Dict[str, Any]]:
            details.update({"decision": "BLOCKED", "reason": reason})
            self._record_payment(details, text)
            return False, text, details

        # Rule 1: MCC must be allowed for the bucket (and not prohibited)
        if mcc in rule["prohibited"]:
            return block(
                "PROHIBITED_MCC",
                f"Transaction Rejection: Prohibited category. {merchant['name']} (MCC {mcc}, "
                f"{rule['prohibited'][mcc]}) cannot be paid from {rule['label']} eâ‚¹.",
            )
        if rule["mccs"] is not None and mcc not in rule["mccs"]:
            return block(
                "PURPOSE_BOUND_MISMATCH",
                f"Transaction Rejection: Purpose-Bound Token Mismatch. {merchant['name']} (MCC {mcc}, "
                f"{merchant['mcc_label']}) is not an authorized vendor for {rule['label']} eâ‚¹ tokens.",
            )

        # Rule 2: terminal must be designated for specialised buckets (blocks cafeteria-style misuse)
        if rule["terminals"] is not None and terminal not in rule["terminals"]:
            return block(
                "TERMINAL_NOT_DESIGNATED",
                f"Transaction Rejection: Terminal '{terminal}' at {merchant['name']} is not a designated "
                f"billing terminal for {rule['label']} eâ‚¹ (parent MCC {mcc} alone is not enough).",
            )

        # Rule 3: sufficient balance in that bucket
        key = bucket.lower()
        available = self.receiver_wallet.get(key, 0.0)
        if available < amount_inr:
            return block(
                "INSUFFICIENT_FUNDS",
                f"Insufficient funds in {rule['label']} bucket. Available: â‚¹{available:,.2f}",
            )

        # Approved: debit the bucket
        self.receiver_wallet[key] = _r2(self.receiver_wallet[key] - amount_inr)
        self.receiver_wallet["total"] = _r2(self.receiver_wallet["total"] - amount_inr)
        self.tier2_spent_inr += amount_inr
        block_rec = self._append_block(
            "SPEND", "Tier 2",
            f"â‚¹{amount_inr:,.2f} {rule['label']} eâ‚¹ â†’ {merchant['name']} (MCC {mcc})",
        )
        text = f"Payment of â‚¹{amount_inr:,.2f} to {merchant['name']} authorized via {rule['label']} eâ‚¹ bucket (MCC {mcc})."
        details.update({"decision": "APPROVED", "reason": "OK", "block_height": block_rec["height"]})
        self._record_payment(details, text)
        return True, text, details

    def pay(self, merchant_id: str, category: str, amount_inr: float) -> Tuple[bool, str, Dict[str, Any]]:
        """Alias kept for main.py compatibility."""
        return self.pay_merchant(merchant_id, category, amount_inr)

    def _record_payment(self, details: Dict[str, Any], text: str) -> None:
        self.payments.append({
            "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
            "merchant": details.get("merchant"),
            "mcc": details.get("mcc"),
            "bucket": details.get("bucket"),
            "amount_inr": details.get("amount_inr"),
            "decision": details.get("decision"),
            "reason": details.get("reason"),
            "message": text,
        })


# Global singleton used by app.main
drunix_chain = CBDCSmartContract()
