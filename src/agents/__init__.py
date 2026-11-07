"""
recon-agents — Multi-agent orchestrator for reconkit recon modules.

Agents use a local Ollama model or any OpenAI-compatible online API to decide
which recon stage to run next based on prior findings. All scans stay gated
behind reconkit's scope file and detection-only pipeline.
"""

__version__ = "2.0.1"
