"""Realistic workload: build a frame, write it as CSV, read it back, aggregate."""
import numpy as np
import pandas as pd

rng = np.random.default_rng(0)
n = 200_000
df = pd.DataFrame({"key": rng.integers(0, 1000, n), "a": rng.random(n), "b": rng.random(n)})
df.to_csv("data.csv", index=False)
back = pd.read_csv("data.csv")
out = back.groupby("key").agg(a=("a", "mean"), b=("b", "sum"))
out.to_csv("summary.csv")
print(len(out))
