import json

class Memory:
    def __init__(self, file="memory.json"):
        self.file = file
        self.data = self.load()

    def load(self):
        try:
            return json.load(open(self.file))
        except:
            return {"hunts": []}

    def save(self):
        json.dump(self.data, open(self.file, "w"), indent=2)

    def add(self, context):
        self.data["hunts"].append({
            "target": context.target,
            "findings": context.findings
        })
        self.save()
