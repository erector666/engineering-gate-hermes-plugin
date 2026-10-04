"""Fail-closed Hermes hooks: only Gate controls and ready instance writes pass."""
from dataclasses import dataclass


@dataclass(frozen=True)
class _ReadinessBinding:
    profile_id: str
    profile_home: str
    state_path: str
    sidecar_path: str
    manager: object
    _seal: object



def _block():
    return {
        "action": "block",
        "message": "Engineering Gate permits only its exact plan-approval control and intercepted writes.",
    }


def pre_tool_call(tool_name: str = "", args=None, **kwargs):
    """Standalone/default hook: allow exact ordinary reads and Gate control only."""
    if tool_name == "gate_approve_plan" and type(args) is dict and set(args) == {"task_id"}:
        return None
    if tool_name == "read_file" and type(args) is dict and set(args) == {"path"}:
        return None
    return _block()


def register_hooks(ctx):
    """Register an isolated fail-closed callback; activation requires adapter proof."""
    state = {"ready": False, "binding": None}
    seal = object()

    def callback(tool_name: str = "", args=None, **kwargs):
        if tool_name == "gate_approve_plan" and type(args) is dict and set(args) == {"task_id"}:
            return None
        if tool_name == "read_file" and type(args) is dict and set(args) == {"path"}:
            return None
        if (state["ready"] and state["binding"] is not None and tool_name == "write_file"
                and type(args) is dict and set(args) == {"path", "content"}):
            return None
        return _block()

    def set_ready(ready: bool, binding=None) -> None:
        valid = (ready is True and type(binding) is _ReadinessBinding
                 and binding._seal is seal and binding.manager is getattr(ctx, "_manager", None))
        state["ready"] = valid
        state["binding"] = binding if valid else None

    def validated_binding(profile_id, profile_home, state_path, sidecar_path):
        return _ReadinessBinding(profile_id, profile_home, state_path, sidecar_path,
                                 getattr(ctx, "_manager", None), seal)

    ctx.register_hook("pre_tool_call", callback)
    ctx.on_unload(lambda: set_ready(False))
    return set_ready, validated_binding


__all__ = ["pre_tool_call", "register_hooks"]
