"""Registry for managing skills"""

import logging
from typing import Dict, Any, Callable, Optional

logger = logging.getLogger(__name__)


class SkillValidationError(Exception):
    """Raised when a skill is invalid"""
    pass


class Registry:
    """Manages skill registration and retrieval"""
    
    def __init__(self):
        self.skills: Dict[str, Dict[str, Any]] = {}
    
    def register(self, skill: Dict[str, Any]) -> None:
        """Register a skill with validation
        
        Args:
            skill: Dictionary with 'name' and 'run' keys
                   'run' must be callable
        
        Raises:
            SkillValidationError: If skill is invalid
        """
        if not isinstance(skill, dict):
            raise SkillValidationError("Skill must be a dictionary")
        
        if "name" not in skill:
            raise SkillValidationError("Skill must have 'name' field")
        
        if "run" not in skill:
            raise SkillValidationError("Skill must have 'run' field")
        
        if not callable(skill["run"]):
            raise SkillValidationError(f"Skill 'run' must be callable, got {type(skill['run'])}")
        
        skill_name = skill["name"]
        self.skills[skill_name] = skill
        logger.info(f"Registered skill: {skill_name}")
    
    def get(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a skill by name"""
        return self.skills.get(name)
    
    def list_skills(self) -> list:
        """Get list of all registered skill names"""
        return list(self.skills.keys())
    
    def __len__(self) -> int:
        return len(self.skills)
    
    def __repr__(self) -> str:
        return f"Registry({len(self.skills)} skills: {', '.join(self.list_skills())})"
