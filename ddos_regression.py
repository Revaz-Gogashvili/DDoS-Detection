import pandas as pd
import re
import matplotlib.pyplot as plt
from sklearn.linear_model import LinearRegression
import numpy as np


def perform_ddos_analysis(log_file='server.log'):
    """
    Parses server logs, performs Linear Regression to establish a traffic baseline,
    and identifies DDoS anomalies based on standard deviation.
    """
    print(f"Starting DDoS Regression Analysis on {log_file}...")

    log_data = []
    try:
        with open(log_file, 'r') as f:
            for line in f:
                # Regex matches the date and time: [YYYY-MM-DD HH:MM:SS]
                match = re.search(r'\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if match:
                    log_data.append(match.group(1))

        if not log_data:
            print("Warning: No valid timestamps found in log file.")
            return

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

    # Regression Modeling
    # We use the index as our X (time steps)
    X = np.arange(len(df_resampled)).reshape(-1, 1)
    y = df_resampled['actual_count'].values

    model = LinearRegression()
    model.fit(X, y)
    df_resampled['predicted'] = model.predict(X)

    # Statistical Anomaly Detection
    # Using 2 standard deviations for the threshold
    std_dev = np.std(y)
    threshold = df_resampled['predicted'] + (2 * std_dev)
    df_resampled['is_ddos'] = df_resampled['actual_count'] > threshold

    ddos_attacks = df_resampled[df_resampled['is_ddos'] == True]

    # Console Output
    print("\n--- IDENTIFIED DDOS ATTACK INTERVALS ---")
    if ddos_attacks.empty:
        print("No DDoS attacks detected. Baseline is stable.")
    else:
        # Displaying only relevant columns for clarity
        print(ddos_attacks[['timestamp', 'actual_count']])
    print("----------------------------------------\n")

    # Visualization
    plt.figure(figsize=(12, 6))
    plt.plot(df_resampled['timestamp'], df_resampled['actual_count'], label='Actual Traffic', color='royalblue',
             alpha=0.7)
    plt.plot(df_resampled['timestamp'], df_resampled['predicted'], label='Regression Trend (Baseline)', color='red',
             linestyle='--')

    if not ddos_attacks.empty:
        plt.scatter(ddos_attacks['timestamp'], ddos_attacks['actual_count'], color='orange',
                    label='DDoS Attack Detected', zorder=5)

    plt.title('Server Traffic: Regression-Based Anomaly Detection')
    plt.xlabel('Time')
    plt.ylabel('Requests Per Minute')
    plt.legend()
    plt.grid(True, linestyle=':', alpha=0.6)

    plt.tight_layout()  # Ensures labels don't get cut off
    plt.savefig('ddos_plot.png')
    print("Plot saved as 'ddos_plot.png'")
    plt.show()


if __name__ == "__main__":
    perform_ddos_analysis()