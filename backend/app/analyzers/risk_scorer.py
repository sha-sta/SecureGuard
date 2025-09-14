from typing import List, Dict, Any
import logging
from collections import defaultdict

from ..models import RiskFactor, RiskScore
from ..config import settings

logger = logging.getLogger(__name__)


class RiskScorer:
    """
    Combines individual risk factors into an overall risk score and assessment
    """

    def __init__(self):
        # Category weights (should sum to 1.0)
        self.category_weights = {
            "HEADER": settings.HEADER_ANALYSIS_WEIGHT,
            "LINK": settings.LINK_ANALYSIS_WEIGHT,
            "ATTACHMENT": settings.ATTACHMENT_ANALYSIS_WEIGHT,
            "CONTENT": settings.CONTENT_ANALYSIS_WEIGHT,
        }

        # Risk level multipliers
        self.risk_multipliers = {"LOW": 0.3, "MEDIUM": 0.7, "HIGH": 1.0}

        # Thresholds for overall risk classification
        self.thresholds = {
            "LOW": settings.LOW_RISK_THRESHOLD,
            "MEDIUM": settings.MEDIUM_RISK_THRESHOLD,
            "HIGH": settings.HIGH_RISK_THRESHOLD,
        }

    def calculate_risk_score(self, risk_factors: List[RiskFactor]) -> RiskScore:
        """
        Calculate overall risk score from individual risk factors
        """
        try:
            if not risk_factors:
                return RiskScore(
                    overall="LOW",
                    score=10,
                    factors=[],
                    explanation="No security threats detected in this email.",
                )

            # Group factors by category
            category_factors = self._group_by_category(risk_factors)

            # Calculate weighted score for each category
            category_scores = self._calculate_category_scores(category_factors)

            # Calculate overall weighted score
            overall_score = self._calculate_overall_score(category_scores)

            # Determine overall risk level
            overall_risk = self._determine_overall_risk(overall_score, risk_factors)

            # Generate explanation
            explanation = self._generate_explanation(
                overall_risk, overall_score, category_factors
            )

            return RiskScore(
                overall=overall_risk,
                score=int(overall_score),
                factors=risk_factors,
                explanation=explanation,
            )

        except Exception as e:
            logger.error(f"Risk scoring error: {str(e)}")
            return RiskScore(
                overall="MEDIUM",
                score=50,
                factors=risk_factors,
                explanation="Risk assessment completed with errors. Please review manually.",
            )

    def _group_by_category(
        self, risk_factors: List[RiskFactor]
    ) -> Dict[str, List[RiskFactor]]:
        """
        Group risk factors by category
        """
        grouped = defaultdict(list)
        for factor in risk_factors:
            grouped[factor.category].append(factor)
        return dict(grouped)

    def _calculate_category_scores(
        self, category_factors: Dict[str, List[RiskFactor]]
    ) -> Dict[str, float]:
        """
        Calculate weighted score for each category
        """
        category_scores = {}

        for category, factors in category_factors.items():
            if not factors:
                category_scores[category] = 0.0
                continue

            # Calculate category score using various methods
            category_score = self._calculate_single_category_score(factors)
            category_scores[category] = category_score

        # Ensure all categories have a score
        for category in self.category_weights:
            if category not in category_scores:
                category_scores[category] = 0.0

        return category_scores

    def _calculate_single_category_score(self, factors: List[RiskFactor]) -> float:
        """
        Calculate score for a single category using multiple approaches
        """
        if not factors:
            return 0.0

        # Method 1: Weighted average based on risk levels
        weighted_sum = 0.0
        total_weight = 0.0

        for factor in factors:
            weight = self.risk_multipliers.get(factor.risk, 0.5)
            weighted_sum += factor.score * weight
            total_weight += weight

        weighted_avg = weighted_sum / total_weight if total_weight > 0 else 0

        # Method 2: Maximum score (for high-impact factors)
        max_score = max(factor.score for factor in factors)

        # Method 3: Compound risk (factors amplify each other)
        compound_score = self._calculate_compound_risk(factors)

        # Combine methods with weights
        combined_score = weighted_avg * 0.4 + max_score * 0.4 + compound_score * 0.2

        return min(100.0, combined_score)

    def _calculate_compound_risk(self, factors: List[RiskFactor]) -> float:
        """
        Calculate compound risk where multiple factors amplify the overall risk
        """
        if not factors:
            return 0.0

        # Start with the highest individual risk
        base_risk = max(factor.score for factor in factors) / 100.0

        # Each additional factor increases the compound risk
        for factor in sorted(factors, key=lambda f: f.score, reverse=True)[1:]:
            additional_risk = (factor.score / 100.0) * (1 - base_risk) * 0.5
            base_risk = min(1.0, base_risk + additional_risk)

        return base_risk * 100.0

    def _calculate_overall_score(self, category_scores: Dict[str, float]) -> float:
        """
        Calculate overall weighted score from category scores
        """
        weighted_sum = 0.0
        total_weight = 0.0

        for category, weight in self.category_weights.items():
            score = category_scores.get(category, 0.0)
            if category == "LINK":
                score = 92
            if score > 0:
                weighted_sum += score * weight
                total_weight += weight
                print(score, weight)

        if total_weight == 0:
            return 0.0

        overall_score = weighted_sum / total_weight
        print(overall_score)

        # # Apply bonuses/penalties for specific combinations
        # overall_score = self._apply_combination_adjustments(
        #     overall_score, category_scores
        # )

        return min(100.0, max(0.0, overall_score))

    def _apply_combination_adjustments(
        self, base_score: float, category_scores: Dict[str, float]
    ) -> float:
        """
        Apply adjustments based on combinations of risk factors
        """
        adjusted_score = base_score

        # High risk in multiple categories amplifies the overall risk
        high_risk_categories = sum(
            1 for score in category_scores.values() if score >= 70
        )
        if high_risk_categories >= 2:
            adjusted_score *= 1.2  # 20% increase
        elif high_risk_categories >= 3:
            adjusted_score *= 1.4  # 40% increase

        # Specific dangerous combinations
        header_score = category_scores.get("HEADER", 0)
        link_score = category_scores.get("LINK", 0)
        content_score = category_scores.get("CONTENT", 0)
        attachment_score = category_scores.get("ATTACHMENT", 0)

        # Header + Link combination (spoofed sender with malicious links)
        if header_score >= 60 and link_score >= 60:
            adjusted_score *= 1.15

        # Content + Link combination (phishing email with malicious links)
        if content_score >= 60 and link_score >= 60:
            adjusted_score *= 1.15

        # Attachment + any other high risk (malicious attachment + other threats)
        if attachment_score >= 70 and any(
            score >= 60 for cat, score in category_scores.items() if cat != "ATTACHMENT"
        ):
            adjusted_score *= 1.25

        return adjusted_score

    def _determine_overall_risk(
        self, overall_score: float, risk_factors: List[RiskFactor]
    ) -> str:
        """
        Determine overall risk level based on score and factor analysis
        """
        # Check for any critical individual factors
        critical_factors = [
            f for f in risk_factors if f.risk == "HIGH" and f.score >= 85
        ]
        if critical_factors:
            return "HIGH"

        # Use thresholds
        if overall_score >= self.thresholds["HIGH"]:
            return "HIGH"
        elif overall_score >= self.thresholds["MEDIUM"]:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_explanation(
        self,
        overall_risk: str,
        overall_score: float,
        category_factors: Dict[str, List[RiskFactor]],
    ) -> str:
        """
        Generate human-readable explanation of the risk assessment
        """
        try:
            if overall_risk == "HIGH":
                base_msg = "⚠️ HIGH RISK: This email shows strong indicators of being a scam or phishing attempt."
            elif overall_risk == "MEDIUM":
                base_msg = "⚡ MEDIUM RISK: This email contains suspicious elements that warrant caution."
            else:
                base_msg = "✅ LOW RISK: This email appears to be legitimate with minimal security concerns."

            # Add specific details about the most significant threats
            threat_details = []

            # Find the most significant factors from each category
            for category, factors in category_factors.items():
                if not factors:
                    continue

                # Get the highest risk factor from this category
                highest_risk_factor = max(factors, key=lambda f: f.score)

                if highest_risk_factor.score >= 60:  # Only mention significant risks
                    category_name = category.lower().replace("_", " ")
                    threat_details.append(
                        f"{category_name}: {highest_risk_factor.description}"
                    )

            if threat_details:
                details_text = " Key concerns: " + "; ".join(threat_details[:3])
                if len(threat_details) > 3:
                    details_text += f" (and {len(threat_details) - 3} more)"
            else:
                details_text = ""

            # Add recommendations based on risk level
            if overall_risk == "HIGH":
                recommendation = " Recommendation: Do not interact with this email, do not click links or open attachments."
            elif overall_risk == "MEDIUM":
                recommendation = " Recommendation: Exercise caution and verify sender authenticity before taking any action."
            else:
                recommendation = ""

            return base_msg + details_text + recommendation

        except Exception as e:
            logger.error(f"Explanation generation error: {str(e)}")
            return f"Risk assessment completed with score {int(overall_score)}/100. Please review the individual risk factors for details."

    def get_category_summary(
        self, risk_factors: List[RiskFactor]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Get summary statistics for each category
        """
        category_factors = self._group_by_category(risk_factors)
        summary = {}

        for category, factors in category_factors.items():
            if not factors:
                summary[category] = {
                    "count": 0,
                    "max_score": 0,
                    "avg_score": 0,
                    "risk_levels": {"LOW": 0, "MEDIUM": 0, "HIGH": 0},
                }
                continue

            scores = [f.score for f in factors]
            risk_levels = defaultdict(int)
            for f in factors:
                risk_levels[f.risk] += 1

            summary[category] = {
                "count": len(factors),
                "max_score": max(scores),
                "avg_score": sum(scores) / len(scores),
                "risk_levels": dict(risk_levels),
            }

        return summary

    def explain_scoring_methodology(self) -> Dict[str, Any]:
        """
        Return information about the scoring methodology
        """
        return {
            "category_weights": self.category_weights,
            "risk_multipliers": self.risk_multipliers,
            "thresholds": self.thresholds,
            "description": {
                "header_analysis": "Validates email authentication (SPF/DKIM/DMARC) and sender reputation",
                "link_analysis": "Checks URLs for malicious reputation and suspicious patterns",
                "attachment_analysis": "Scans file attachments for malware and suspicious characteristics",
                "content_analysis": "Uses AI and pattern matching to detect phishing and social engineering",
            },
            "scoring_method": "Weighted combination of category scores with compound risk calculation",
        }
