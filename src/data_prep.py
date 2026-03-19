import pandas as pd
import numpy as np
import os
from sklearn.model_selection import train_test_split

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')

df = pd.read_csv(os.path.join(DATA_DIR, 'NF-UQ-NIDS.csv'))

print(df.sample(n=5, random_state=1))

