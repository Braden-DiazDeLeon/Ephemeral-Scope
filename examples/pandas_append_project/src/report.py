import pandas as pd


def build_frame():
    frame = pd.DataFrame({"a": [1]})
    return frame.append({"a": 2})
