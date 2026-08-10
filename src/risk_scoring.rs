/// Behavioral Risk Scoring for Microsoft Identity Zero Trust
/// Aggregates real-time signals into a normalized risk score [0.0, 1.0].

#[derive(Debug, Clone)]
pub struct RiskSignal {
    pub signal_type: SignalType,
    pub weight: f32,
    pub value: f32, // 0.0 = no risk, 1.0 = max risk
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SignalType {
    AnonymousIp,
    UnusualTravel,
    MalwareInfectedIp,
    SuspiciousApiUsage,
    TokenReplay,
    ImpossibleTravel,
    BruteForce,
}

#[derive(Debug, Clone)]
pub struct RiskEvaluation {
    pub score: f32,
    pub signals: Vec<RiskSignal>,
    pub recommendation: RiskRecommendation,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RiskRecommendation {
    Allow,
    RequireStepUpAuth,
    Block,
    RequireAdminConsent,
}

pub struct RiskScoringEngine {
    signals: Vec<RiskSignal>,
    threshold_step_up: f32,
    threshold_block: f32,
}

impl RiskScoringEngine {
    pub fn new(threshold_step_up: f32, threshold_block: f32) -> Self {
        RiskScoringEngine {
            signals: Vec::new(),
            threshold_step_up,
            threshold_block,
        }
    }

    pub fn add_signal(&mut self, signal: RiskSignal) {
        self.signals.push(signal);
    }

    /// Aggregate signals into a weighted risk score
    pub fn evaluate(&self) -> RiskEvaluation {
        if self.signals.is_empty() {
            return RiskEvaluation {
                score: 0.0,
                signals: vec![],
                recommendation: RiskRecommendation::Allow,
            };
        }

        let total_weight: f32 = self.signals.iter().map(|s| s.weight).sum();
        let weighted_sum: f32 = self.signals.iter().map(|s| s.value * s.weight).sum();
        let score = if total_weight > 0.0 {
            (weighted_sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        };

        let recommendation = if score >= self.threshold_block {
            RiskRecommendation::Block
        } else if score >= self.threshold_step_up {
            RiskRecommendation::RequireStepUpAuth
        } else {
            RiskRecommendation::Allow
        };

        RiskEvaluation {
            score,
            signals: self.signals.clone(),
            recommendation,
        }
    }

    /// Reset signals for new evaluation
    pub fn reset(&mut self) {
        self.signals.clear();
    }
}

impl Default for RiskScoringEngine {
    fn default() -> Self {
        Self::new(0.5, 0.8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_low_risk() {
        let mut engine = RiskScoringEngine::new(0.5, 0.8);
        engine.add_signal(RiskSignal {
            signal_type: SignalType::SuspiciousApiUsage,
            weight: 1.0,
            value: 0.3,
        });

        let eval = engine.evaluate();
        assert_eq!(eval.recommendation, RiskRecommendation::Allow);
    }

    #[test]
    fn test_high_risk_block() {
        let mut engine = RiskScoringEngine::new(0.5, 0.8);
        engine.add_signal(RiskSignal {
            signal_type: SignalType::MalwareInfectedIp,
            weight: 1.0,
            value: 0.9,
        });

        let eval = engine.evaluate();
        assert_eq!(eval.recommendation, RiskRecommendation::Block);
    }

    #[test]
    fn test_medium_risk_step_up() {
        let mut engine = RiskScoringEngine::new(0.5, 0.8);
        engine.add_signal(RiskSignal {
            signal_type: SignalType::UnusualTravel,
            weight: 1.0,
            value: 0.6,
        });

        let eval = engine.evaluate();
        assert_eq!(eval.recommendation, RiskRecommendation::RequireStepUpAuth);
    }

    #[test]
    fn test_weighted_aggregation() {
        let mut engine = RiskScoringEngine::new(0.5, 0.8);
        engine.add_signal(RiskSignal {
            signal_type: SignalType::AnonymousIp,
            weight: 2.0,
            value: 0.8,
        });
        engine.add_signal(RiskSignal {
            signal_type: SignalType::SuspiciousApiUsage,
            weight: 1.0,
            value: 0.2,
        });

        let eval = engine.evaluate();
        // (0.8*2 + 0.2*1) / 3 = 1.8/3 = 0.6
        assert!((eval.score - 0.6).abs() < 0.01);
        assert_eq!(eval.recommendation, RiskRecommendation::RequireStepUpAuth);
    }
}