from concurrent.futures import ThreadPoolExecutor

class Parallel:
    def __init__(self, registry):
        self.registry = registry

    def run(self, skills, context):
        def run_skill(name):
            skill = self.registry.get(name)
            return skill["run"](context) if skill else None

        with ThreadPoolExecutor(max_workers=5) as ex:
            return list(ex.map(run_skill, skills))
