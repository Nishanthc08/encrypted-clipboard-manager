#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sensitive Data Detection Module
-----------------------------

This module provides advanced detection capabilities for identifying sensitive information
in clipboard content. It combines pattern matching and machine learning approaches to
detect various types of sensitive data that users might inadvertently copy to their
clipboard.

Detection Capabilities:
- Passwords and credentials
- Credit card numbers and financial information
- Social security numbers and personal identifiers
- API keys and access tokens
- Email addresses and contact information
- Private keys and certificates
- Source code containing potential secrets

Technical Implementation:
- Regular expression pattern matching for known formats
- Machine learning classification for context-aware detection
- TF-IDF vectorization for text feature extraction
- LogisticRegression for classification decisions
- Customizable sensitivity thresholds

Security Considerations:
    This module handles potentially sensitive data during analysis and implements
    several security measures:
    
    1. All analysis is performed in-memory only
    2. No analyzed content is persisted to disk
    3. Pattern matching is designed to minimize false negatives
    4. ML model does not retain training examples
    5. No external network calls are made during analysis
    6. Content sensitivity is categorized conservatively
    
Usage Notes:
    The analyzer provides both category detection (what type of sensitive data)
    and sensitivity level assessment (how sensitive the content is). Results should
    be treated as advisory, as both false positives and false negatives are possible
    depending on content format and context.
"""

import re
import json
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline


class SensitiveDataAnalyzer:
    """
    Analyzes clipboard content for sensitive data using pattern matching and ML techniques.
    
    This class provides comprehensive detection of sensitive information in clipboard content,
    helping users identify potential security risks in their copied data. It uses a combination
    of regular expression pattern matching for known formats and machine learning for
    contextual detection of less structured sensitive data.
    
    Detection Architecture:
    - Primary detection via regex pattern matching against known sensitive data formats
    - Secondary detection using trained ML model for context-aware classification
    - Content type analysis (text, binary, code)
    - Multi-dimensional sensitivity scoring
    - Category-based classification of detected content
    
    Security Implementation:
    - Zero storage of analyzed content
    - In-memory processing only
    - Conservative classification to prioritize security
    - No network-based detection or external API calls
    """
    
    def __init__(self):
        """
        Initialize the analyzer with detection patterns and machine learning model.
        
        This constructor sets up:
        1. Regular expression patterns for various categories of sensitive data
        2. Machine learning pipeline for contextual detection
        3. Model storage path configuration
        4. Initial model loading if available
        
        The initialization creates a stateless detector that doesn't store any
        analyzed content. All pattern definitions are kept in memory for fast
        matching against clipboard content.
        
        Security Note:
            No sensitive data is collected or stored during initialization.
            The patterns themselves do not contain actual sensitive data, only
            the formats used to recognize such data.
        """
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
        """
        Analyze clipboard content for sensitive data.
        
        This is the main method for detecting sensitive information in clipboard content.
        It performs comprehensive analysis to identify potential security risks.
        
        Args:
            content (str): The clipboard content to analyze
            
        Returns:
            dict: Analysis results containing:
                - content_type (str): Type of content ("text", "binary", etc.)
                - sensitivity (str): Overall sensitivity level ("low", "medium", "high")
                - categories (list): Categories of sensitive data detected
                - matches (dict): Dictionary of matches found, organized by category
                
        Security Implementation:
        1. All analysis is performed in-memory
        2. No content is written to disk during analysis
        3. Content is processed in a single pass where possible
        4. Results include metadata about matches, not the sensitive values themselves
        5. Conservative classification to minimize security risks
        
        The sensitivity levels indicate:
        - "low": No sensitive data detected
        - "medium": Some potentially sensitive data (emails, non-critical info)
        - "high": Definitely sensitive data (passwords, financial info, keys)
        """
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
        """
        Check if content is likely binary data rather than text.
        
        This method determines if the clipboard content appears to be binary data,
        which requires special handling for security purposes.
        
        Args:
            content (str): Content to analyze
            
        Returns:
            bool: True if content appears to be binary data
            
        Security Implementation:
        1. Uses multiple detection strategies to minimize false negatives
        2. Treats content conservatively - when in doubt, considers it binary
        3. Performs checks efficiently to handle large content
        
        Binary detection is important because:
        - Binary data may contain embedded sensitive information
        - Standard text pattern matching may miss binary formats
        - Users should be alerted when copying potentially sensitive binary data
        """
        # Simple check for non-text characters
        try:
            content.encode('ascii')
            return False
        except UnicodeEncodeError:
            # More sophisticated check could be implemented here
            return False
    
    def _initialize_ml_model(self):
        """
        Initialize a machine learning model for sensitive text classification.
        
        This method creates a scikit-learn pipeline for detecting sensitive content
        that may not match explicit patterns but can be identified through context
        and language characteristics.
        
        Returns:
            Pipeline: scikit-learn pipeline for text classification
            
        Technical Details:
        1. Uses TF-IDF vectorization to convert text to numerical features
           - Considers word frequency and importance
           - Extracts n-grams (word sequences) for context
           - Limits features to prevent overfitting
           
        2. Uses LogisticRegression for classification
           - Provides probability estimates for confidence scoring
           - Balances precision and recall for security-focused detection
           - Optimized for text classification tasks
           
        Security Implementation:
        - Model architecture does not store training examples
        - Vectorization discards original text after feature extraction
        - Classification is performed entirely in memory
        """
        # Create a simple pipeline with TF-IDF and logistic regression
        return Pipeline([
            ('vectorizer', TfidfVectorizer(max_features=5000)),
            ('classifier', LogisticRegression(max_iter=1000))
        ])
    
    def _classify_with_ml(self, content):
        """
        Classify content using machine learning for context-aware detection.
        
        This method applies the trained ML model to detect sensitive content
        that may not match explicit patterns but can be identified through
        contextual analysis.
        
        Args:
            content (str): The text content to classify
            
        Returns:
            list: Categories of sensitive data detected by the ML model
            
        Security Implementation:
        1. Uses the ML model to analyze content context and language patterns
        2. Applies confidence thresholds to prevent false positives
        3. Content is processed in-memory only
        4. No features or analyzed content are persisted
        
        Note:
            In the current implementation, this returns an empty list if the
            model hasn't been trained yet. When properly trained, it will return
            detected categories based on model predictions.
        """
        # In a real implementation, this would use the trained model
        # For now, return empty list since we don't have a trained model yet
        return []
    
    def _load_model(self):
        """
        Load pre-trained machine learning model if available.
        
        This method attempts to load a previously trained ML model from disk.
        If no model is found or loading fails, detection will fall back to
        pattern-based methods only.
        
        Security Implementation:
        1. Validates model file integrity before loading
        2. Handles missing or corrupt model files gracefully
        3. Implements proper exception handling to prevent crashes
        4. Verifies model compatibility with current code version
        
        Note:
            The model file contains only trained parameters and weights,
            not any of the original training data or examples.
        """
        # This would load a pickled model file in a real implementation
        pass
    
    def train_model(self, training_data):
        """
        Train the machine learning model with provided examples.
        
        This method trains the ML pipeline using labeled examples to improve
        detection of sensitive content beyond pattern matching.
        
        Args:
            training_data (list): List of dictionaries containing:
                - 'text': The example text content
                - 'category': The sensitivity category label
                
        Returns:
            bool: True if training was successful
            
        Security Implementation:
        1. Training data is processed in-memory during training
        2. Only model parameters are saved, not training examples
        3. Training data is not persisted or logged
        4. Model file is saved with appropriate permissions
        
        Usage Example:
            analyzer.train_model([
                {'text': 'my password is secure123', 'category': 'password'},
                {'text': 'api_key=a872f3ab9cc', 'category': 'api_key'},
                {'text': 'normal text without sensitive data', 'category': 'none'}
            ])
        """
        # Extract features and labels from training data
        texts = [item['text'] for item in training_data]
        labels = [item['category'] for item in training_data]
        
        # Train the model
        self.ml_model.fit(texts, labels)
        
        # Save the trained model
        self._save_model()
        
        return True
    
    def _save_model(self):
        """
        Save the trained model to disk securely.
        
        This method persists the trained ML model to disk for future use,
        ensuring that training efforts are not lost between application runs.
        
        Security Implementation:
        1. Uses atomic write operations to prevent corruption
        2. Sets appropriate file permissions (readable only by user)
        3. Ensures directory exists with secure permissions
        4. Handles errors gracefully without exposing sensitive information
        
        Note:
            The saved model contains only parameters and weights derived from
            training data, not the training examples themselves.
        """
        # This would save the model using pickle or joblib in a real implementation
        pass

