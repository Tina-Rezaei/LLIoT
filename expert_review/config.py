from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

FINAL_LABELS = BASE_DIR / "manual_review" / "labels" / "final_labels.json"
FINAL_LABELS_TIE_BREAK = BASE_DIR / "manual_review" / "labels" / "final_labels_after_tie_breaking.json"
RESOLVED_CONFLICTS = BASE_DIR / "llm_human_analysis" / "conflicts" / "resolved_conflicts.json"
FINAL_LABELS_AFTER_CONFLICT_RESOLVE = BASE_DIR / "manual_review" / "labels" / "final_labels_after_conflict_resolve.json"
LLM_OUTPUT_PATH = BASE_DIR / "LLM_classification" / "LLM_output"
OUTPUT_DIR = BASE_DIR / "LLM_classification" / "LLM_output"
PROMPT_DIR = BASE_DIR / "LLM_classification" / "prompts"
LLM_EVALUATION_PATH = BASE_DIR / "LLM_classification" / "LLM_evaluation_result"
EXPERT_REVIEWS = BASE_DIR / "manual_review" / "reviews" / "expert_reviews.json"
