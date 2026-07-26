"""
quantum_ml.py — Adversarial Quantum Threat Detection
Uses Support Vector Machines (SVM) trained on adversarial quantum circuit features.
"""
import numpy as np
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler

def block_to_features(block, risk_score, state_probs):
    """
    Maps a code block and its quantum simulation results to a feature vector.
    Features:
    - Von Neumann Entropy-based Risk Score
    - Top 8 quantum state probabilities (Amplitude signature)
    - Logical Depth (Lines of code / Complexity)
    - Entanglement Complexity (Unique tainted calls)
    """
    feats = []
    # 1. Risk Score
    feats.append(risk_score)
    
    # 2. Quantum State Signature (Pad/Truncate to 8)
    probs = list(state_probs)
    if len(probs) < 8:
        probs += [0.0] * (8 - len(probs))
    feats.extend(probs[:8])
    
    # 3. Complexity Metrics
    # Handle both dict (legacy parser) and object (future) if needed
    body_len = len(block.get("body", [])) if isinstance(block, dict) else 0
    calls_len = len(block.get("calls", [])) if isinstance(block, dict) else 0
    feats.append(body_len)
    feats.append(calls_len)
    
    return np.array(feats)

def train_detection_model(feature_matrix):
    """
    Trains a One-Class SVM to detect anomalies (Quantum Bombs) 
    that deviate from 'normal' quantum circuit patterns.
    """
    # Scale features
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(feature_matrix)
    
    # OneClassSVM
    # nu=0.1 implies ~10% of data might be outliers (threats) in training set
    model = OneClassSVM(kernel='rbf', gamma='auto', nu=0.1)
    model.fit(X_scaled)
    
    return model, scaler

def predict_threats(model, scaler, feature_matrix):
    """
    -1 = Adversarial Quantum Threat (Bomb), 1 = Benign
    """
    if len(feature_matrix) == 0:
        return [], []
        
    X_scaled = scaler.transform(feature_matrix)
    preds = model.predict(X_scaled)
    scores = model.decision_function(X_scaled) # Distance to hyperplane
    return preds, scores
