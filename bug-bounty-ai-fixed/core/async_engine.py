import asyncio
import time
from concurrent.futures import ThreadPoolExecutor

from core.context import Context


class AsyncEngine:
    """Runs skills in parallel for faster analysis"""

    def __init__(self, registry):
        self.registry = registry
        self.executor = ThreadPoolExecutor(max_workers=5)

    async def run_skill(self, skill_name: str, context: Context):
        """Run a single skill in thread pool"""

        skill = self.registry.get(skill_name)

        if not skill:
            context.skipped_skills.append(skill_name)
            return

        start = time.time()

        try:
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                self.executor,
                skill["run"],
                context
            )

            context.executed_skills.append(skill_name)

            context.add_execution(
                skill_name,
                time.time() - start,
                True
            )

        except Exception as e:
            context.add_error(skill_name, str(e))

            context.add_execution(
                skill_name,
                time.time() - start,
                False
            )

    async def run_all(self, skill_names: list[str], context: Context):
        """Run multiple skills in parallel"""

        tasks = [
            self.run_skill(name, context)
            for name in skill_names
        ]

        await asyncio.gather(*tasks)

        return context
