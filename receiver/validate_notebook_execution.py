"""
Test headless execution of all code cells in receiver_secure_exam_exchange.ipynb
"""

import json
from pathlib import Path

def test_notebook():
    nb = json.loads(Path("receiver_secure_exam_exchange.ipynb").read_text(encoding="utf-8"))
    env = {}
    for i, cell in enumerate(nb["cells"]):
        if cell["cell_type"] == "code":
            code = "".join(cell["source"])
            # skip pip install shell escapes in exec
            code_lines = [l for l in code.splitlines() if not l.strip().startswith("!")]
            clean_code = "\n".join(code_lines)
            print(f"Executing Code Cell {i}...")
            try:
                exec(clean_code, env)
            except Exception as e:
                print(f"ERROR in cell {i}: {e}")
                raise

    print("All code cells in notebook executed successfully!")

if __name__ == "__main__":
    test_notebook()
