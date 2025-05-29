#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sensitive data detection module for the Encrypted Clipboard Manager.
"""

import re
import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class SensitiveDataAnalyzer:
    """Analyzes clipboard content for sensitive data."""
    
    def __init__(self):
        """Initialize the analyzer with regex patterns and ML model."""
        # Define regex patterns for common sensitive data
        self.patterns = {
            "password": [
                r"(?i)password\s*[:=]\s*\S+",
                r"(?i)pass\s*[:=]\s*\S+",
                r"(?i)pwd\s*[:=]\s*\S+"
            ],
            "credit_card": [
                r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
                r"\b\d{16}\b"
            ],
            "api_key": [
                r"(?i)api[-_]?key\s*[:=]\s*\S+",
                r"(?i)api[-_]?secret\s*[:=]\s*\S+",
                r"(?i)access[-_]?token\s*[:=]\s*\S+"
            ],
            "social_security": [
                r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"
            ],
            "email": [
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
            ]
        }
        
        # Initialize ML model for classification
        self.ml_model = self._initialize_ml_model()
        
        # Path for storing trained model
        self.model_path = os.path.expanduser("~/.encrypted_clipboard_manager_model")
        
        # Try to load pre-trained model if it exists
        self._load_model()
    
    def analyze(self, content):
        """Analyze clipboard content for sensitive data."""
        # Initialize result
        result = {
            "content_type": "text",
            "sensitivity": "low",
            "categories": [],
            "matches": {}
        }
        
        # Check content type (simple check for now)
        if self._is_binary(content):
            result["content_type"] = "binary"
            return result
        
        # Check for sensitive data using regex
        for category, patterns in self.patterns.items():
            matches = []
            for pattern in patterns:
                found = re.findall(pattern, content)
                if found:
                    matches.extend(found)
            
            if matches:
                result["categories"].append(category)
                result["matches"][category] = matches
        
        # Use ML model for additional classification
        ml_categories = self._classify_with_ml(content)
        for category in ml_categories:
            if category not in result["categories"]:
                result["categories"].append(category)
        
        # Set sensitivity level based on findings
        if len(result["categories"]) > 0:
            if any(c in ["password", "credit_card", "social_security", "api_key"] 
                   for c in result["categories"]):
                result["sensitivity"] = "high"
            else:
                result["sensitivity"] = "medium"
        
        return result
    
    def _is_binary(self, content):
        """Check if content is likely binary data."""
        # Simple check for non-text characters
        try:
            content.encode('ascii')
            return False
        except UnicodeEncodeError:
            # More sophisticated check could be implemented here
            return False
    
    def _initialize_ml_model(self):
        """Initialize a machine learning model for text classification."""
        # Create a simple pipeline with TF-IDF and logistic regression
        return Pipeline([
            ('vectorizer', TfidfVectorizer(max_features=5000)),
            ('classifier', LogisticRegression(max_iter=1000))
        ])
    
    def _classify_with_ml(self, content):
        """Classify content using machine learning."""
        # In a real implementation, this would use the trained model
        # For now, return empty list since we don't have a trained model yet
        return []
    
    def _load_model(self):
        """Load pre-trained model if available."""
        # This would load a pickled model file in a real implementation
        pass
    
    def train_model(self, training_data):
        """Train the ML model with provided data."""
        # Extract features and labels from training data
        texts = [item['text'] for item in training_data]
        labels = [item['category'] for item in training_data]
        
        # Train the model
        self.ml_model.fit(texts, labels)
        
        # Save the trained model
        self._save_model()
        
        return True
    
    def _save_model(self):
        """Save the trained model to disk."""
        # This would save the model using pickle or joblib in a real implementation
        pass

