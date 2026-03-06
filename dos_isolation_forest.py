import pandas as pd
import re
import matplotlib.pyplot as plt
from sklearn.ensemble import IsolationForest
import numpy as np


def perform_ddos_analysis_iforest(log_file='server.log'):
    print("Starting DDoS Isolation Forest Analysis...")

    log_data = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if match:
                    log_data.append(match.group(1))
    except FileNotFoundError:
        print(f"Error: {log_file} not found.")
        return

    # Data Preparation
    df = pd.DataFrame(log_data, columns=['timestamp'])
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df['count'] = 1

    # Aggregate to 1-minute intervals
    df_resampled = df.resample('1min', on='timestamp').count().rename(columns={'count': 'actual_count'})
    df_resampled = df_resampled.reset_index()

    # --- ISOLATION FOREST LOGIC ---
    # We use 'actual_count' as the feature.
    # We reshape it because the model expects a 2D array.
    X = df_resampled[['actual_count']].values

    # contamination: The proportion of outliers in the data set.
    # Since we saw about 4 minutes of attack in a short log, let's set it to 0.1 (10%)
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

    # fit_predict returns -1 for outliers and 1 for inliers
    df_resampled['anomaly'] = model.fit_predict(X)
    df_resampled['is_ddos'] = df_resampled['anomaly'] == -1

    ddos_attacks = df_resampled[df_resampled['is_ddos'] == True]

    # Console Output
    print("\n--- IDENTIFIED DDOS ATTACK INTERVALS (ISOLATION FOREST) ---")
    if ddos_attacks.empty:
        print("No DDoS attacks detected.")
    else:
        print(ddos_attacks[['timestamp', 'actual_count']])
    print("-----------------------------------------------------------\n")

    # Visualization
    plt.figure(figsize=(14, 7))
    plt.plot(df_resampled['timestamp'], df_resampled['actual_count'], label='Actual Traffic', color='royalblue')

    # Isolation Forest doesn't have a single "line," but we can plot the average count
    # to give the eye a reference point, similar to the regression line.
    mean_traffic = df_resampled['actual_count'].mean()
    plt.axhline(y=mean_traffic, color='gray', linestyle='--', label='Average Traffic')

    if not ddos_attacks.empty:
        plt.scatter(ddos_attacks['timestamp'], ddos_attacks['actual_count'],
                    color='red', label='DDoS Attack (Anomaly)', zorder=5)

    plt.title('Traffic Anomaly Detection (Isolation Forest)')
    plt.xlabel('Time')
    plt.ylabel('Requests Per Minute')
    plt.legend()
    plt.savefig('ddos_plot_iforest.png')
    plt.show()


if __name__ == "__main__":
    perform_ddos_analysis_iforest()