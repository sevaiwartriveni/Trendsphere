"""
ml/predictor.py
────────────────────────────────────────────────────────
Direct ML predictor — no FastAPI needed.
Handles the existing TrendPredictor wrapper pkl format.

Usage in app.py:
    from ml.predictor import predictor
    results = predictor.predict(signals_list)
"""

import os, sys, logging
import numpy as np
import pandas as pd
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# ── Status thresholds ────────────────────────────────
VIRAL   = 0.85
HOT     = 0.65
RISING  = 0.40
STABLE  = 0.20

FEATURE_COLUMNS = [
    "view_velocity","search_momentum","wishlist_velocity","cart_velocity",
    "wishlist_rate","cart_rate","purchase_rate","search_to_view",
    "engagement_score","acceleration","social_proof","price_sensitivity",
    "raw_views_recent","raw_searches_recent","category_heat",
]


# ── Feature engineering ──────────────────────────────

def _vel(recent, prev):
    if prev == 0:
        return 1.0 if recent > 0 else 0.0
    return float(np.clip((recent - prev) / (prev + 1e-9) / 5.0, -1.0, 1.0))

def _rate(n, d):
    return 0.0 if d == 0 else float(np.clip(n / (d + 1e-9), 0.0, 1.0))

def _build_features(signals: List[Dict]) -> pd.DataFrame:
    rows = []
    for s in signals:
        vl = max(s.get("views_last_7d", 0), 1)
        vv = _vel(s.get("views_last_7d",    0), s.get("views_prev_7d",    0))
        sm = _vel(s.get("searches_last_7d", 0), s.get("searches_prev_7d", 0))
        wv = _vel(s.get("wishlist_last_7d", 0), s.get("wishlist_prev_7d", 0))
        cv = _vel(s.get("cart_last_7d",     0), s.get("cart_prev_7d",     0))
        wr = _rate(s.get("wishlist_last_7d", 0), vl)
        cr = _rate(s.get("cart_last_7d",     0), vl)
        pr = _rate(s.get("purchases_last_7d",0), vl)
        sv = _rate(s.get("searches_last_7d", 0), vl)
        eng = 0.20*vv + 0.25*sm + 0.30*wr + 0.25*cr
        acc = sum(1 for v in [vv,sm,wv,cv] if v > 0) / 4.0
        rt  = float(s.get("avg_rating") or 0)
        rv  = int(s.get("review_count") or 0)
        sp  = (rt * np.log1p(rv)) / (5.0 * np.log1p(10000))
        px  = float(s.get("price") or 0)
        ps  = float(np.clip(1.0 - np.log1p(px)/np.log1p(100000), 0, 1)) if px > 0 else 0.5
        rows.append({
            "product_id":          str(s.get("product_id","")),
            "category":            str(s.get("category","general")),
            "view_velocity":       vv,  "search_momentum":     sm,
            "wishlist_velocity":   wv,  "cart_velocity":       cv,
            "wishlist_rate":       wr,  "cart_rate":           cr,
            "purchase_rate":       pr,  "search_to_view":      sv,
            "engagement_score":    eng, "acceleration":        acc,
            "social_proof":        float(sp), "price_sensitivity":   ps,
            "raw_views_recent":    np.log1p(s.get("views_last_7d",    0)),
            "raw_searches_recent": np.log1p(s.get("searches_last_7d", 0)),
            "category_heat":       0.0,
        })
    df = pd.DataFrame(rows)
    if not df.empty:
        m   = df.groupby("category")["engagement_score"].transform("mean")
        std = df.groupby("category")["engagement_score"].transform("std").replace(0, 1)
        df["category_heat"] = ((df["engagement_score"] - m) / std).clip(-3, 3) / 3.0
    return df

def _classify(score: float) -> str:
    if score >= VIRAL:  return "viral"
    if score >= HOT:    return "hot"
    if score >= RISING: return "rising"
    if score >= STABLE: return "stable"
    return "cold"

def _confidence(sig: Dict, score: float) -> float:
    vol  = sum([sig.get("views_last_7d",0), sig.get("searches_last_7d",0),
                sig.get("wishlist_last_7d",0), sig.get("cart_last_7d",0)])
    vc   = float(np.clip(np.log1p(vol) / np.log1p(5000), 0.1, 1.0))
    sc   = abs(score - 0.5) * 2.0
    return float(np.clip(0.6*vc + 0.4*sc, 0.1, 0.99))


# ── Predictor class ──────────────────────────────────

class TrendPredictor:
    """
    Loads the saved model and predicts trend scores.
    Supports both pkl formats:
      - Old: TrendPredictor wrapper (with .regressor attribute)
      - New: bare XGBRegressor (with .feature_importances_)
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.getenv("MODEL_PATH", "models/saved/trend_model.pkl")
        self._regressor  = None
        self._scaler     = None
        self._anomaly    = None
        self._loaded     = False
        self._accuracy_metrics: dict = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.model_path):
            logger.warning(
                f"⚠️  Model not found at '{self.model_path}'. "
                "Run:  python train.py"
            )
            return
        try:
            # Add project root so old TrendPredictor class can unpickle
            root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if root not in sys.path:
                sys.path.insert(0, root)

            import joblib
            raw = joblib.load(self.model_path)

            # ── Format A: old TrendPredictor wrapper ──
            if hasattr(raw, "regressor") and hasattr(raw.regressor, "predict"):
                self._regressor = raw.regressor
                self._scaler    = getattr(raw, "scaler",           None)
                self._anomaly   = getattr(raw, "anomaly_detector", None)
                self._accuracy_metrics = getattr(raw, "_accuracy_metrics", {})
                logger.info("✅ Model loaded (TrendPredictor wrapper)")

            # ── Format B: bare XGBRegressor (new train.py) ──
            elif hasattr(raw, "predict") and hasattr(raw, "feature_importances_"):
                self._regressor = raw
                self._scaler    = getattr(raw, "scaler",           None)
                self._anomaly   = getattr(raw, "anomaly_detector", None)
                self._accuracy_metrics = getattr(raw, "_accuracy_metrics", {})
                logger.info("✅ Model loaded (XGBRegressor direct)")

            elif hasattr(raw, "predict"):
                self._regressor = raw
                logger.info("✅ Model loaded (generic predictor)")

            else:
                logger.error(f"❌ Unknown model format: {type(raw)}")
                return

            self._loaded = True

        except Exception as e:
            logger.error(f"❌ Failed to load model: {e}")
            logger.error("   Run: python train.py")

    def is_ready(self) -> bool:
        return self._loaded and self._regressor is not None

    def predict(self, signals: List[Dict]) -> List[Dict]:
        if not signals:
            return []
        if not self.is_ready():
            logger.warning("Model not ready — returning fallback scores")
            return self._fallback(signals)

        df = _build_features(signals)
        X  = df[FEATURE_COLUMNS].fillna(0.0)

        # Score with XGBoost
        try:
            raw_scores = np.clip(self._regressor.predict(X), 0.0, 1.0).astype(float)
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            return self._fallback(signals)

        # Anomaly detection
        anomalies = np.zeros(len(signals), dtype=bool)
        if self._scaler is not None and self._anomaly is not None:
            try:
                Xs     = self._scaler.transform(X)
                labels = self._anomaly.predict(Xs)
                anomalies = (labels == -1)
            except Exception as e:
                logger.debug(f"Anomaly detection skipped: {e}")

        results = []
        for i, sig in enumerate(signals):
            score = float(raw_scores[i])
            feat  = df.iloc[i]
            an    = bool(anomalies[i])
            if an:
                score = float(np.clip(score * 1.15, 0.0, 1.0))
            results.append({
                "product_id":       str(sig.get("product_id", "")),
                "trend_score":      round(score, 4),
                "trend_status":     _classify(score),
                "confidence":       round(_confidence(sig, score), 4),
                "view_velocity":    round(float(feat["view_velocity"]),   4),
                "search_momentum":  round(float(feat["search_momentum"]), 4),
                "wishlist_signal":  round(float(feat["wishlist_rate"]),   4),
                "cart_intent":      round(float(feat["cart_rate"]),       4),
                "anomaly_detected": an,
                "forecast_7d":      round(
                    float(np.clip(score + float(feat["acceleration"]) * 0.15, 0.0, 1.0)),
                    4
                ),
            })

        results.sort(key=lambda r: r["trend_score"], reverse=True)
        return results

    def _fallback(self, signals: List[Dict]) -> List[Dict]:
        return [{
            "product_id":       str(s.get("product_id", "")),
            "trend_score":      0.3,
            "trend_status":     "stable",
            "confidence":       0.1,
            "view_velocity":    0.0,
            "search_momentum":  0.0,
            "wishlist_signal":  0.0,
            "cart_intent":      0.0,
            "anomaly_detected": False,
            "forecast_7d":      0.3,
        } for s in signals]


# ── Singleton ─────────────────────────────────────────
predictor = TrendPredictor()
