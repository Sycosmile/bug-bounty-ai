"""Dynamic skill loader"""

import importlib
import logging
from pathlib import Path
from config import SKILLS_DIR
from core.registry import Registry, SkillValidationError

logger = logging.getLogger(__name__)


def load_skills(registry: Registry) -> Registry:
    """Dynamically discover and load all skills
    
    Args:
        registry: Registry to register skills into
    
    Returns:
        Registry with loaded skills
    """
    if not SKILLS_DIR.exists():
        logger.warning(f"Skills directory not found: {SKILLS_DIR}")
        return registry
    
    skill_files = sorted(SKILLS_DIR.glob("*.py"))
    logger.info(f"Discovering skills in {SKILLS_DIR}")
    
    loaded_count = 0
    
    for file_path in skill_files:
        file_name = file_path.name
        
        # Skip __init__.py and private files
        if file_name.startswith("_"):
            continue
        
        module_name = file_name[:-3]  # Remove .py
        
        try:
            module = importlib.import_module(f"skills.{module_name}")
            
            if not hasattr(module, "skill"):
                logger.warning(f"Skill module '{module_name}' has no 'skill' export")
                continue
            
            skill_obj = module.skill
            registry.register(skill_obj)
            loaded_count += 1
            logger.debug(f"Loaded skill: {skill_obj.get('name', module_name)}")
        
        except SkillValidationError as e:
            logger.error(f"Skill validation failed for '{module_name}': {e}")
        except ImportError as e:
            logger.error(f"Failed to import skill '{module_name}': {e}")
        except Exception as e:
            logger.error(f"Unexpected error loading skill '{module_name}': {e}")
    
    logger.info(f"Successfully loaded {loaded_count} skills")
    return registry
