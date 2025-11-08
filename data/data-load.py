import pandas as pd

# Load the Excel file
excel_file_path = 'urls.xlsx'
df = pd.read_excel(excel_file_path, engine='openpyxl')

# Drop rows with missing or blank URLs
df = df.dropna(subset=['URL'])

# Keep only the columns you want to save
df_cleaned = df[['URL', 'Label']]

# Remove whitespace and ensure URL is a string
df_cleaned['URL'] = df_cleaned['URL'].astype(str).str.strip()

# Save to CSV properly (append or overwrite as needed)
csv_file_path = 'phishing_data.csv'

# Append to existing file without headers (but avoid blank/extra columns)
df_cleaned.to_csv(csv_file_path, mode='a', index=False, header=False)

print(f"✅ Clean data appended to: {csv_file_path}")
