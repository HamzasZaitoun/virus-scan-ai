import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, roc_auc_score
import joblib

# اقرأ البيانات
df = pd.read_csv('scans.csv')

# الميزات والـ label
features = ['suspicious_links_count','sql_injection_count','infected_files_count','bad_ssl','vt_positive_votes','xss_count','http_anomalies']
X = df[features]
y = df['label']

# قسّم البيانات
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# درّب الموديل
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X_train, y_train)

# قيّم النتائج
y_pred = clf.predict(X_test)
y_proba = clf.predict_proba(X_test)[:,1]

print("Classification report:")
print(classification_report(y_test, y_pred))
print("ROC AUC:", roc_auc_score(y_test, y_proba))

# احفظ الموديل
joblib.dump(clf, 'threat_model.pkl')
print("✅ Model saved as threat_model.pkl")
