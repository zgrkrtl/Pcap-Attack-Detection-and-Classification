import pandas as pd

TARGET = 5000

dataset = pd.read_csv('dataset/dataset2.csv')

print('Before Balancing data: ')
print(dataset['label'].value_counts().sort_index())

balanced_dfs = []

for label, group in dataset.groupby('label'):
    if len(group) >= TARGET:
        sampled = group.sample(n=TARGET, random_state=42)
    else:
        sampled = group.sample(n=TARGET, replace=True, random_state=42)
    balanced_dfs.append(sampled)

balanced = pd.concat(balanced_dfs, ignore_index=True)

balanced = balanced.sample(frac=1, random_state=42).reset_index(drop=True)

balanced.to_csv('dataset/balanced_dataset.csv', index=False)

print("\nAfter Balancing: ")
print(balanced['label'].value_counts().sort_index())
print(f"\nFinal shape: {balanced.shape}")

print(balanced.columns.tolist())
