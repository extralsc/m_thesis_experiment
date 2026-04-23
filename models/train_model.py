"""
Train multiple IDS classifier models for thesis comparison.
Run once before docker-compose up.

Usage:  python models/train_model.py
Output: models/random_forest.pkl
        models/decision_tree.pkl
        models/svm.pkl
        models/knn.pkl
"""

import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

N_FEATURES = 10
N_NORMAL = 5000
N_ATTACK = 5000

print("Generating synthetic training data...")

normal = np.random.normal(loc=0.3, scale=0.1, size=(N_NORMAL, N_FEATURES))
attack = np.random.normal(loc=0.8, scale=0.15, size=(N_ATTACK, N_FEATURES))
X = np.vstack([normal, attack])
y = np.concatenate([np.zeros(N_NORMAL), np.ones(N_ATTACK)])

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

MODELS = {
    "random_forest": RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42, n_jobs=-1),
    "decision_tree": DecisionTreeClassifier(max_depth=10, random_state=42),
    "svm":           SVC(kernel="rbf", probability=True, random_state=42),
    "knn":           KNeighborsClassifier(n_neighbors=5, n_jobs=-1),
}

for name, model in MODELS.items():
    print(f"\n--- Training {name} ---")
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, target_names=["NORMAL", "ATTACK"]))
    path = f"models/{name}.pkl"
    joblib.dump(model, path)
    print(f"Saved -> {path}")

print("\nAll models trained and saved.")
